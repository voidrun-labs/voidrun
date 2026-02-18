package machine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"voidrun/internal/config"
	"voidrun/internal/model"
	"voidrun/pkg/network"
	"voidrun/pkg/timer"
)

// Create handles Fresh Boot (API Injection) and Restore (API Restore)
func Create(cfg config.Config, spec model.SandboxSpec, overlayPath string, restorePath string) error {
	defer timer.Track("Sandbox Start (Total)")()
	fmt.Printf("   [CONFIG] Bridge Name: '%s'\n", cfg.Network.BridgeName)
	fmt.Printf("   [CONFIG] TAP Prefix: '%s'\n", cfg.Network.TapPrefix)
	fmt.Printf("   [CONFIG] Instances Dir: '%s'\n", cfg.Paths.InstancesDir)

	overlayPath, _ = filepath.Abs(overlayPath)

	// Use centralized path helpers
	socketPath := GetSocketPath(spec.ID)
	logPath := GetLogPath(spec.ID)
	pidPath := GetPIDPath(spec.ID)
	tapPath := GetTapPath(spec.ID)
	vsockPath := GetVsockPath(spec.ID)

	// Generate MAC based on IP
	macAddr := network.GenerateMAC(spec.IPAddress)
	log.Printf("   [Net] Generated MAC %s for IP %s\n", macAddr, spec.IPAddress)

	// Create TAP interface (Detached state)
	// We do NOT attach to bridge yet to avoid EBUSY errors in CLH
	tapName, err := network.CreateRandomTap(macAddr, cfg.Network.TapPrefix)
	if err != nil {
		return err
	}

	log.Printf("   [Net] Created TAP interface %s\n", tapName)

	// Save TAP name for cleanup later
	os.WriteFile(tapPath, []byte(tapName), 0644)

	// 3. Start "Empty" Cloud Hypervisor Process
	clhPath, _ := exec.LookPath("cloud-hypervisor")
	args := []string{
		"--api-socket", socketPath,
		"--log-file", logPath,
	}

	fmt.Printf(">> [Native] Spawning empty CLH process (API Mode)...\n")
	cmd := exec.Command(clhPath, args...)

	// Redirect IO
	logFile, _ := os.Create(logPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // Daemonize

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("process start failed: %v", err)
	}

	// Save PID before releasing process handle
	pid := cmd.Process.Pid
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(pid)), 0644); err != nil {
		cmd.Process.Kill()
		return err
	}
	cmd.Process.Release()

	// 4. Wait for Socket to appear
	client := NewAPIClient(socketPath)
	if err := client.WaitForSocket(2 * time.Second); err != nil {
		// Read log for debugging
		logs, _ := os.ReadFile(logPath)
		Stop(spec.ID) // Cleanup
		return fmt.Errorf("VM crashed on start. Logs:\n%s", string(logs))
	}

	// 5. Inject Configuration via API
	if restorePath != "" {
		// === RESTORE MODE ===
		fmt.Printf("   [+] Restoring from snapshot: %s\n", restorePath)
		absRestorePath, _ := filepath.Abs(restorePath)

		// Restore Config
		restoreConfig := &RestoreConfig{
			SourceURL: fmt.Sprintf("file://%s", absRestorePath),
			// We re-attach network config here
			Net: []NetConfig{{Tap: tapName, Mac: macAddr}},
		}

		clhClient := NewCLHClient(socketPath)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := clhClient.VmRestore(ctx, restoreConfig); err != nil {
			Stop(spec.ID)
			return fmt.Errorf("restore API failed: %w", err)
		}

	} else {
		// === FRESH BOOT MODE ===
		fmt.Println("   [+] Injecting Configuration via API...")

		iface := "eth0"
		gateway := cfg.Network.GetCleanGateway()
		netmask := cfg.Network.GetNetmask()

		hostname := "voidrun"

		kernelIPArgs := fmt.Sprintf(
			"ip=%s::%s:%s:%s:%s:off",
			spec.IPAddress,
			gateway,
			netmask,
			hostname,
			iface,
		)

		envVars := ""

		debugConsole := cfg.Sandbox.DebugBootConsole
		if debugConsole {
			log.Printf("   [Boot] Debug console enabled (vm log: %s)", logPath)
		}
		consoleArgs := "console=hvc0"
		if debugConsole {
			consoleArgs = "console=ttyS0 console=hvc0"
		}

		cmdLine := fmt.Sprintf(
			"%s root=/dev/vda rw init=/sbin/init net.ifnames=0 biosdevname=0 %s %s",
			consoleArgs,
			kernelIPArgs,
			envVars,
		)
		log.Printf("   [Kernel] CmdLine: %s\n", cmdLine)

		payload := PayloadConfig{
			Kernel:  cfg.Paths.KernelPath,
			Cmdline: cmdLine, // Use Cmdline (lowercase 'l') for JSON marshaling
		}
		if cfg.Paths.InitrdPath != "" {
			initrdPath, _ := filepath.Abs(cfg.Paths.InitrdPath)
			payload.Initramfs = initrdPath
		}
		log.Printf("   [CLH] Kernel: %s\n", payload.Kernel)
		if payload.Initramfs != "" {
			log.Printf("   [CLH] Initrd: %s\n", payload.Initramfs)
		}
		log.Printf("   [CLH] CmdLine: %s\n", payload.Cmdline)

		// Create Config Struct
		vmCfg := VmConfig{
			Payload: &payload,
			Cpus: &CpusConfig{
				BootVcpus: spec.CPUs,
				MaxVcpus:  spec.CPUs,
			},
			Memory: &MemoryConfig{
				Size:      int64(spec.MemoryMB) * 1024 * 1024,
				Shared:    true,
				Mergeable: true,
				Prefault:  false,
			},
			Disks: []DiskConfig{
				{Path: overlayPath},
			},
			// Remove IP from here (Kernel handles it), just pass Layer 2 info
			Net: []NetConfig{{Tap: tapName, Mac: macAddr}},
			Rng: &RngConfig{Src: "/dev/urandom"},
			Serial: &ConsoleConfig{Mode: func() string {
				if debugConsole {
					return "Tty"
				}
				return "Null"
			}()},
			Console: &ConsoleConfig{Mode: func() string {
				if debugConsole {
					return "Tty"
				}
				return "Null"
			}()},
			Vsock: &VsockConfig{
				Cid:    getCidFromIP(spec.IPAddress),
				Socket: vsockPath,
			},
		}

		// A. Send Config using new CLHClient
		clhClient := NewCLHClient(socketPath)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := clhClient.VmCreate(ctx, &vmCfg); err != nil {
			Stop(spec.ID)
			return fmt.Errorf("vm.create failed: %w", err)
		}

		// B. Send Boot Signal
		fmt.Println("   [+] Sending Boot Signal...")
		if err := clhClient.VmBoot(ctx); err != nil {
			Stop(spec.ID)
			return fmt.Errorf("vm.boot failed: %w", err)
		}
	}

	fmt.Printf("   [Net] Config Bridge Name: %s\n", cfg.Network.BridgeName)
	fmt.Printf("   [Net] Attaching %s to bridge %s...\n", tapName, cfg.Network.BridgeName)
	if err := network.EnableTap(cfg.Network.BridgeName, tapName); err != nil {
		Stop(spec.ID)
		return fmt.Errorf("network attach failed (bridge: %s, tap: %s): %v", cfg.Network.BridgeName, tapName, err)
	}

	fmt.Printf("   [+] VM Active! PID: %d, Tap: %s\n", pid, tapName)
	return nil
}

// Stop gracefully shuts down the VM via CLH API (keeps hypervisor and network for restart)
func Stop(id string) error {
	defer timer.Track("lifecycle: Sandbox Stop")()
	socketPath := GetSocketPath(id)

	// 1. Gracefully shutdown VM via CLH API (keeps hypervisor process running)
	client := NewCLHClient(socketPath)
	if client.IsSocketAvailable() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := client.VmShutdown(ctx); err != nil {
			fmt.Printf("Warning: VmShutdown failed for %s: %v\n", id, err)
		}
	}
	fmt.Printf("   [+] VM %s Stopped (CLH process and TAP interface preserved).\n", id)
	return nil
}

// Start boots a VM that is in shutdown state
func Start(id string) error {
	defer timer.Track("lifecycle: Sandbox Start")()
	socketPath := GetSocketPath(id)

	client := NewCLHClient(socketPath)
	if !client.IsSocketAvailable() {
		return fmt.Errorf("VM socket not available. Is the hypervisor process running?")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check current state
	state, err := client.GetState(ctx)
	if err != nil {
		return fmt.Errorf("failed to get VM state: %w", err)
	}

	// Can boot from Created or Shutdown states
	if state != VmStateShutdown && state != "Created" {
		return fmt.Errorf("VM must be in shutdown or created state to start (current state: %s)", state)
	}

	// Boot the VM
	fmt.Printf("   [+] Starting VM %s (state: %s)...\n", id, state)
	if err := client.VmBoot(ctx); err != nil {
		return fmt.Errorf("vm.boot failed: %w", err)
	}

	// Wait for VM to reach running state
	// if err := WaitForVMState(ctx, client, VmStateRunning, 5*time.Second); err != nil {
	// 	fmt.Printf("Warning: VM did not reach running state: %v\n", err)
	// }

	fmt.Printf("   [+] VM %s Started.\n", id)
	return nil
}

// Delete removes the VM via CLH API and cleans up all files
func Delete(id string) error {
	socketPath := GetSocketPath(id)
	pidPath := GetPIDPath(id)
	tapPath := GetTapPath(id)

	// 1. Delete VM via CLH API (this will also shutdown the VM)
	client := NewCLHClient(socketPath)
	if client.IsSocketAvailable() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := client.VmDelete(ctx); err != nil {
			fmt.Printf("Warning: VmDelete failed for %s: %v\n", id, err)
		}
	}

	// 2. Kill the CLH process
	if data, err := os.ReadFile(pidPath); err == nil {
		pid, _ := strconv.Atoi(string(data))
		if process, err := os.FindProcess(pid); err == nil {
			process.Signal(syscall.SIGTERM)
		}
		os.Remove(pidPath)
	}

	// 3. Clean up TAP interface
	if tapData, err := os.ReadFile(tapPath); err == nil {
		tapName := string(tapData)
		network.DeleteTap(tapName)
		os.Remove(tapPath)
	}

	// 4. Delete the instance directory
	instanceDir := GetInstanceDir(id)
	fmt.Printf(">> Deleting instance %s at %s\n", id, instanceDir)

	if err := os.RemoveAll(instanceDir); err != nil {
		return fmt.Errorf("failed to delete directory: %w", err)
	}

	fmt.Printf("   [+] VM %s fully deleted.\n", id)
	return nil
}

// Pause pauses a running VM
func Pause(id string) error {
	client := NewCLHClientForSandbox(id)
	if !client.IsSocketAvailable() {
		return fmt.Errorf("Sandbox not running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return client.VmPause(ctx)
}

// Resume resumes a paused VM
func Resume(id string) error {
	client := NewCLHClientForSandbox(id)
	if !client.IsSocketAvailable() {
		return fmt.Errorf("Sandbox not running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return client.VmResume(ctx)
}

// Info returns the raw JSON info from Cloud Hypervisor
func Info(id string) (string, error) {
	client := NewCLHClientForSandbox(id)
	if !client.IsSocketAvailable() {
		return "", fmt.Errorf("Sandbox not running (socket missing)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := client.VmInfo(ctx)
	if err != nil {
		return "", err
	}

	// Convert to JSON string for backward compatibility
	jsonBytes, err := json.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("failed to marshal info: %w", err)
	}
	return string(jsonBytes), nil
}

// CreateSnapshot creates a snapshot of a running VM
func CreateSnapshot(sbxID string) error {
	log.Printf(">> Creating snapshot for Sandbox ID: %s\n", sbxID)

	client := NewCLHClientForSandbox(sbxID)
	if !client.IsSocketAvailable() {
		return fmt.Errorf("Sandbox socket not found. Is Sandbox running?")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check Sandbox state
	state, err := client.GetState(ctx)
	log.Printf("   [+] Current State: %s\n", state)
	if err != nil {
		return fmt.Errorf("failed to get Sandbox state: %w", err)
	}

	if state != VmStateRunning && state != VmStatePaused {
		return fmt.Errorf("cannot snapshot Sandbox in state: %s (Must be Running or Paused)", state)
	}

	// Pause if running
	if state == VmStateRunning {
		if err := client.VmPause(ctx); err != nil {
			return fmt.Errorf("pause failed: %w", err)
		}
		fmt.Println("   [+] Sandbox Paused")
	}

	// Prepare directories using path helpers
	timestamp := time.Now().Format("20060102-150405")
	snapDir := filepath.Join(GetSnapshotsDir(sbxID), timestamp)
	if err := os.MkdirAll(snapDir, 0755); err != nil {
		return err
	}

	tempStateDir := GetSnapshotTempDir(sbxID)
	_ = os.RemoveAll(tempStateDir)
	if err := os.MkdirAll(tempStateDir, 0755); err != nil {
		return fmt.Errorf("failed to prepare snapshot temp dir: %w", err)
	}

	fmt.Printf(">> Snapshotting to %s\n", snapDir)

	// Trigger snapshot
	snapshotURL := fmt.Sprintf("file://%s", tempStateDir)
	if err := client.VmSnapshot(ctx, snapshotURL); err != nil {
		if state == VmStateRunning {
			resumeCtx, resumeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = client.VmResume(resumeCtx)
			resumeCancel()
		}
		return fmt.Errorf("snapshot failed: %w", err)
	}
	fmt.Println("   [+] Memory Dumped")

	// Copy disk and finalize snapshot before resuming the VM to keep RAM+disk consistent.
	if err := finalizeSnapshot(sbxID, snapDir, tempStateDir); err != nil {
		if state == VmStateRunning {
			resumeCtx, resumeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			resumeErr := client.VmResume(resumeCtx)
			resumeCancel()
			if resumeErr != nil {
				return fmt.Errorf("snapshot finalize failed: %w (resume failed: %v)", err, resumeErr)
			}
		}
		return err
	}

	// Resume only after snapshot is fully finalized.
	if state == VmStateRunning {
		resumeCtx, resumeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := client.VmResume(resumeCtx)
		resumeCancel()
		if err != nil {
			return fmt.Errorf("resume failed: %w", err)
		}
		fmt.Println("   [+] Sandbox Resumed")
	}

	return nil
}

// Restore creates a new VM from a snapshot (cold or live restore)
func Restore(cfg config.Config, newID, snapshotPath, ip string, cold bool, cpu, memoryMB int) error {
	newInstanceDir := GetInstanceDir(newID)
	log.Printf(">> Restoring Sandbox ID: %s from Snapshot: %s\n", newID, snapshotPath)

	if _, err := os.Stat(newInstanceDir); err == nil {
		return fmt.Errorf("Sandbox ID %s already exists", newID)
	}

	if err := os.MkdirAll(newInstanceDir, 0755); err != nil {
		return fmt.Errorf("failed to create instance dir: %w", err)
	}

	// Restore disk using path helpers
	srcDisk := filepath.Join(snapshotPath, "overlay.qcow2")
	dstDisk := GetOverlayPath(newID)

	fmt.Println("   [+] Copying Disk...")
	if err := exec.Command("cp", srcDisk, dstDisk).Run(); err != nil {
		os.RemoveAll(newInstanceDir)
		return fmt.Errorf("disk copy failed: %w", err)
	}

	// Logic Branch: Cold vs Live
	var dstState string
	if !cold {
		// Live restore: Copy RAM state
		srcState := filepath.Join(snapshotPath, "state")
		dstState = filepath.Join(newInstanceDir, "snapshot_state")

		fmt.Printf("   [+] Copying RAM State from %s to %s\n", srcState, dstState)
		if err := exec.Command("cp", "-r", srcState, dstState).Run(); err != nil {
			os.RemoveAll(newInstanceDir)
			return fmt.Errorf("state copy failed: %w", err)
		}
	} else {
		fmt.Println("   [+] Cold Boot Mode: Discarding old RAM.")
	}

	// Config
	spec := model.SandboxSpec{
		ID:        newID,
		IPAddress: ip,
		CPUs:      cpu,
		MemoryMB:  memoryMB,
	}

	// Start process
	if err := Create(cfg, spec, dstDisk, dstState); err != nil {
		return err
	}

	// Send Resume (only for live restore)
	if !cold {
		fmt.Println("   [+] Waiting for socket to resume...")
		client := NewCLHClientForSandbox(newID)

		if err := client.WaitForSocket(2 * time.Second); err != nil {
			return fmt.Errorf("socket timed out waiting for resume: %w", err)
		}

		// Give API a tiny moment to accept connections
		time.Sleep(5 * time.Millisecond)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := client.VmResume(ctx); err != nil {
			fmt.Printf("   [!] Resume warning: %v\n", err)
		} else {
			fmt.Println("   [+] Sandbox Resumed!")
		}
	}

	return nil
}

// getCidFromIP generates a CID from an IP address for vsock
func getCidFromIP(ipStr string) uint64 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	// Take the last byte and add offset (3 is minimum, 1000 is safe)
	return uint64(ip[3]) + 1000
}

// finalizeSnapshot copies disk and moves state files into their final snapshot layout.
func finalizeSnapshot(sbxID, snapDir, tempStateDir string) error {
	srcDisk := GetOverlayPath(sbxID)
	dstDisk := filepath.Join(snapDir, "overlay.qcow2")

	log.Printf("   [+] Copying disk to snapshot...\n")
	if err := exec.Command("cp", srcDisk, dstDisk).Run(); err != nil {
		_ = os.RemoveAll(snapDir)
		return fmt.Errorf("disk copy failed: %w", err)
	}
	log.Println("   [+] Disk Cloned")

	// Move state files
	finalStateDir := filepath.Join(snapDir, "state")
	if err := os.Rename(tempStateDir, finalStateDir); err != nil {
		_ = os.RemoveAll(snapDir)
		return fmt.Errorf("state move failed: %w", err)
	}

	// Lock state files (read-only)
	if err := filepath.Walk(finalStateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		return os.Chmod(path, 0444)
	}); err != nil {
		return fmt.Errorf("failed to lock snapshot state files: %w", err)
	}

	log.Printf("   [+] Snapshot finalized: %s\n", snapDir)
	return nil
}
