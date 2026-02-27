package machine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"voidrun/internal/config"
	"voidrun/internal/model"
	"voidrun/pkg/network"
	"voidrun/pkg/timer"
)

const defaultNetDeviceID = "net0"

func ConfigureNetwork(cfg config.Config, spec *model.SandboxSpec) error {

	fmt.Printf("   [CONFIG] Bridge Name: '%s'\n", cfg.Network.BridgeName)
	fmt.Printf("   [CONFIG] TAP Prefix: '%s'\n", cfg.Network.TapPrefix)
	fmt.Printf("   [CONFIG] Instances Dir: '%s'\n", cfg.Paths.InstancesDir)

	// Use centralized path helpers
	tapPath := GetTapPath(spec.ID)

	// Generate MAC based on IP
	macAddr := network.GenerateMAC(spec.IPAddress)
	log.Printf("   [Net] Generated MAC %s for IP %s\n", macAddr, spec.IPAddress)

	// Create TAP interface (Detached state)
	// We do NOT attach to bridge yet to avoid EBUSY errors in CLH
	tapName, err := network.CreateRandomTap(macAddr, cfg.Network.TapPrefix)
	if err != nil {
		return err
	}

	spec.TapName = tapName
	spec.MacAddress = macAddr

	log.Printf("   [Net] Created TAP interface %s\n", tapName)

	// Save TAP name for cleanup later
	os.WriteFile(tapPath, []byte(tapName), 0644)

	return nil
}

func CreateFromSnapshot(cfg config.Config, spec model.SandboxSpec) error {
	defaultBaseSnapshotDir := cfg.Paths.DefaultBaseSnapshot
	baseOverlay := path.Join(defaultBaseSnapshotDir, "overlay.qcow2")
	baseSnapshot := path.Join(defaultBaseSnapshotDir, "memory")

	log.Printf(">> Restoring from snapshot. Base Overlay: %s, Base Snapshot: %s\n", baseOverlay, baseSnapshot)
	if _, err := os.Stat(baseOverlay); os.IsNotExist(err) {
		return fmt.Errorf("base overlay missing at path: %s (ensure you have created the base snapshot)", baseOverlay)
	}
	if _, err := os.Stat(baseSnapshot); os.IsNotExist(err) {
		return fmt.Errorf("base snapshot missing at path: %s (ensure you have created the base snapshot)", baseSnapshot)
	}

	// copy base overlay to new location for CLH to use (we don't want to modify the original base snapshot)
	overlayPath := GetOverlayPath(spec.ID)
	if err := os.MkdirAll(GetInstanceDir(spec.ID), 0755); err != nil {
		return fmt.Errorf("failed to create instance dir: %w", err)
	}
	log.Printf("   [+] Copying base overlay to %s\n", overlayPath)
	cp := func() {
		defer timer.Track("Copy Base Overlay")()
		if out, err := exec.Command("cp", baseOverlay, overlayPath).CombinedOutput(); err != nil {
			// return fmt.Errorf("failed to copy base overlay: %w: %s", err, string(out))
			log.Printf("❌ Failed to copy base overlay: %v, output: %s\n", err, string(out))
		}
	}

	cp()

	// Create the VM using the copied overlay and the base snapshot for RAM state
	// if err := Create(cfg, spec, overlayPath, baseSnapshot); err != nil {
	// 	return fmt.Errorf("failed to create VM from snapshot: %w", err)
	// }

	tapName := spec.TapName
	vsockPath := GetVsockPath(spec.ID)

	fmt.Printf("   [+] Restoring from snapshot: %s\n", baseSnapshot)
	absRestorePath, _ := filepath.Abs(baseSnapshot)
	if err := rewriteRestoreState(absRestorePath, overlayPath, tapName, vsockPath); err != nil {
		Stop(spec.ID)
		return fmt.Errorf("restore state rewrite failed: %w", err)
	}

	// Use centralized path helpers
	logPath := GetLogPath(spec.ID)
	pidPath := GetPIDPath(spec.ID)
	// vsockPath := GetVsockPath(spec.ID)pw

	// 3. Start "Empty" Cloud Hypervisor Process
	clhPath, _ := exec.LookPath("cloud-hypervisor")
	args := []string{
		"--api-socket", GetSocketPath(spec.ID),
		"--restore", fmt.Sprintf("file://%s", absRestorePath),
		"--kernel", cfg.Paths.KernelPath,
		"--memory", fmt.Sprintf("size=%dM,mergeable=on,shared=on", spec.MemoryMB),
		"--cpus", fmt.Sprintf("boot=%d,max=%d", spec.CPUs, spec.CPUs),
		"--disk", fmt.Sprintf("path=%s", overlayPath),
		"--net", fmt.Sprintf("tap=%s,mac=%s", tapName, spec.MacAddress),
		"--vsock", fmt.Sprintf("cid=%d,socket=%s", getCidFromIP(spec.IPAddress), vsockPath),
		"--log-file", GetLogPath(spec.ID),
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

	if err := network.EnableTap(cfg.Network.BridgeName, tapName); err != nil {
		Stop(spec.ID)
		return fmt.Errorf("network attach failed (bridge: %s, tap: %s): %v", cfg.Network.BridgeName, tapName, err)
	}

	fmt.Printf("   [+] VM Active! PID: %d, Tap: %s\n", tapName, pid)

	return nil
}

// Create handles Fresh Boot (API Injection) and Restore (API Restore)
func Create(cfg config.Config, spec model.SandboxSpec, overlayPath string, restorePath string) error {
	defer timer.Track("Sandbox Start (Total)")()

	overlayPath, _ = filepath.Abs(overlayPath)

	// Use centralized path helpers
	socketPath := GetSocketPath(spec.ID)
	logPath := GetLogPath(spec.ID)
	pidPath := GetPIDPath(spec.ID)
	vsockPath := GetVsockPath(spec.ID)

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

	tapName := spec.TapName
	macAddr := spec.MacAddress
	log.Printf("   [Create] spec.TapName=%q, spec.MacAddress=%q, restorePath=%q\n", tapName, macAddr, restorePath)

	// 5. Inject Configuration via API
	if restorePath != "" {
		// === RESTORE MODE ===
		fmt.Printf("   [+] Restoring from snapshot: %s\n", restorePath)
		absRestorePath, _ := filepath.Abs(restorePath)
		if err := rewriteRestoreState(absRestorePath, overlayPath, tapName, vsockPath); err != nil {
			Stop(spec.ID)
			return fmt.Errorf("restore state rewrite failed: %w", err)
		}

		// Restore Config
		restoreConfig := &RestoreConfig{
			SourceURL: fmt.Sprintf("file://%s", absRestorePath),
			// We re-attach network config here
			Net: []NetConfig{{ID: defaultNetDeviceID, Tap: tapName, Mac: macAddr}},
		}

		// Live restore can take longer than normal API operations.
		// Keep client timeout aligned with restore context to avoid premature client aborts.
		restoreTimeout := 2 * time.Minute
		clhClient := NewCLHClientWithTimeout(socketPath, restoreTimeout)
		ctx, cancel := context.WithTimeout(context.Background(), restoreTimeout)
		defer cancel()

		if err := clhClient.VmRestore(ctx, restoreConfig); err != nil {
			Stop(spec.ID)
			return fmt.Errorf("restore API failed: %w", err)
		}

	} else {
		// === FRESH BOOT MODE ===
		fmt.Println("   [+] Injecting Configuration via API...")

		debugConsole := cfg.Sandbox.DebugBootConsole

		cmdLine := strings.TrimSpace(cfg.Sandbox.KernelCmdline)
		log.Printf("   [Kernel] CmdLine: %s\n", cmdLine)

		payload := PayloadConfig{
			Kernel:  cfg.Paths.KernelPath,
			Cmdline: cmdLine,
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
			Net: []NetConfig{{ID: defaultNetDeviceID, Tap: tapName, Mac: macAddr}},
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

	socketPath := GetSocketPath(sbxID)
	client := NewCLHClientWithTimeout(socketPath, 2*time.Minute)
	if !client.IsSocketAvailable() {
		return fmt.Errorf("Sandbox socket not found. Is Sandbox running?")
	}

	// Check Sandbox state
	stateCtx, stateCancel := context.WithTimeout(context.Background(), 5*time.Second)
	state, err := client.GetState(stateCtx)
	stateCancel()
	log.Printf("   [+] Current State: %s\n", state)
	if err != nil {
		return fmt.Errorf("failed to get Sandbox state: %w", err)
	}

	if state != VmStateRunning && state != VmStatePaused {
		return fmt.Errorf("cannot snapshot Sandbox in state: %s (Must be Running or Paused)", state)
	}

	// Pause if running
	if state == VmStateRunning {
		pauseCtx, pauseCancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := client.VmPause(pauseCtx)
		pauseCancel()
		if err != nil {
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
		_ = os.RemoveAll(snapDir)
		return fmt.Errorf("failed to prepare snapshot temp dir: %w", err)
	}

	fmt.Printf(">> Snapshotting to %s\n", snapDir)

	// Trigger snapshot
	snapshotURL := fmt.Sprintf("file://%s", tempStateDir)
	snapshotCtx, snapshotCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	err = client.VmSnapshot(snapshotCtx, snapshotURL)
	snapshotCancel()
	if err != nil {
		cleanupErr := cleanupPaths(snapDir, tempStateDir)
		if state == VmStateRunning {
			resumeCtx, resumeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = client.VmResume(resumeCtx)
			resumeCancel()
		}
		if cleanupErr != nil {
			return fmt.Errorf("snapshot failed: %w (cleanup failed: %v)", err, cleanupErr)
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

	dstDisk := ""

	cc := func() error {
		defer timer.Track("copy disk & other")()
		if _, err := os.Stat(newInstanceDir); err == nil {
			return fmt.Errorf("Sandbox ID %s already exists", newID)
		}

		if err := os.MkdirAll(newInstanceDir, 0755); err != nil {
			return fmt.Errorf("failed to create instance dir: %w", err)
		}

		// Restore disk using path helpers
		srcDisk := filepath.Join(snapshotPath, "overlay.qcow2")
		dstDisk = GetOverlayPath(newID)

		fmt.Println("   [+] Copying Disk...")
		if err := exec.Command("cp", srcDisk, dstDisk).Run(); err != nil {
			os.RemoveAll(newInstanceDir)
			return fmt.Errorf("disk copy failed: %w", err)
		}

		return nil
	}

	if err := cc(); err != nil {
		return err
	}
	// Logic Branch: Cold vs Live
	var dstState string
	if !cold {
		// Live restore: Copy RAM state
		srcState := filepath.Join(snapshotPath, "state")
		dstState = filepath.Join(newInstanceDir, "snapshot_state")

		fmt.Printf("   [+] Copying RAM State from %s to %s\n", srcState, dstState)
		if err := exec.Command("cp", "-r", srcState, dstState).Run(); err != nil {
			_ = os.RemoveAll(newInstanceDir)
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

	// Configure network (creates TAP device)
	log.Printf("   [Restore] Before ConfigureNetwork: spec.TapName=%q, spec.MacAddress=%q\n", spec.TapName, spec.MacAddress)
	if err := ConfigureNetwork(cfg, &spec); err != nil {
		_ = os.RemoveAll(newInstanceDir)
		return fmt.Errorf("network config failed: %w", err)
	}
	log.Printf("   [Restore] After ConfigureNetwork: spec.TapName=%q, spec.MacAddress=%q\n", spec.TapName, spec.MacAddress)

	// Start process
	if err := Create(cfg, spec, dstDisk, dstState); err != nil {
		// Ensure host-side resources (tap/pid/socket) are fully cleaned on failed restore.
		_ = Delete(newID)
		_ = network.DeleteTap(spec.TapName)
		_ = os.RemoveAll(newInstanceDir)
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

func cleanupPaths(paths ...string) error {
	var firstErr error
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
			log.Printf("   [!] Failed to clean up %s: %v", path, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

type rewritePair struct {
	old string
	new string
}

func rewriteRestoreState(restorePath, newDiskPath, newTapName, newVsockPath string) error {
	defer timer.Track("rewriteRestoreState")()
	configPath := filepath.Join(restorePath, "config.json")
	rawConfig, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config.json: %w", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return fmt.Errorf("parse config.json: %w", err)
	}

	var replacements []rewritePair

	if disks, ok := cfg["disks"].([]any); ok {
		for _, diskEntry := range disks {
			disk, ok := diskEntry.(map[string]any)
			if !ok {
				continue
			}
			if old, ok := disk["path"].(string); ok {
				old = strings.TrimSpace(old)
				if old != "" {
					replacements = append(replacements, rewritePair{old: old, new: newDiskPath})
				}
			}
			disk["path"] = newDiskPath
		}
	}

	if nets, ok := cfg["net"].([]any); ok {
		for _, netEntry := range nets {
			netCfg, ok := netEntry.(map[string]any)
			if !ok {
				continue
			}
			if old, ok := netCfg["tap"].(string); ok {
				old = strings.TrimSpace(old)
				if old != "" {
					replacements = append(replacements, rewritePair{old: old, new: newTapName})
				}
			}
			netCfg["tap"] = newTapName
		}
	}

	if vsock, ok := cfg["vsock"].(map[string]any); ok {
		if old, ok := vsock["socket"].(string); ok {
			old = strings.TrimSpace(old)
			if old != "" {
				replacements = append(replacements, rewritePair{old: old, new: newVsockPath})
			}
		}
		vsock["socket"] = newVsockPath
	}

	// Some CLH versions persist fs sockets in state. Keep them instance-local.
	if fsEntries, ok := cfg["fs"].([]any); ok {
		for _, fsEntry := range fsEntries {
			fsCfg, ok := fsEntry.(map[string]any)
			if !ok {
				continue
			}
			old, ok := fsCfg["socket"].(string)
			if !ok {
				continue
			}
			old = strings.TrimSpace(old)
			if old == "" {
				continue
			}
			base := filepath.Base(old)
			newSocket := filepath.Join(filepath.Dir(newVsockPath), base)
			replacements = append(replacements, rewritePair{old: old, new: newSocket})
			fsCfg["socket"] = newSocket
		}
	}

	normalized := dedupeReplacements(replacements)

	updatedConfig, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config.json: %w", err)
	}

	if err := writeRewriteTarget(configPath, updatedConfig); err != nil {
		return err
	}

	statePath := filepath.Join(restorePath, "state.json")
	if err := rewriteStateFile(statePath, normalized); err != nil {
		return err
	}

	return nil
}

func dedupeReplacements(in []rewritePair) []rewritePair {
	unique := make(map[string]string, len(in))
	for _, p := range in {
		old := strings.TrimSpace(p.old)
		newVal := strings.TrimSpace(p.new)
		if old == "" || newVal == "" || old == newVal {
			continue
		}
		unique[old] = newVal
	}

	out := make([]rewritePair, 0, len(unique))
	for old, newVal := range unique {
		out = append(out, rewritePair{old: old, new: newVal})
	}

	// Replace longer paths first to avoid partial substitutions.
	slices.SortFunc(out, func(a, b rewritePair) int {
		if len(a.old) == len(b.old) {
			if a.old < b.old {
				return -1
			}
			if a.old > b.old {
				return 1
			}
			return 0
		}
		if len(a.old) > len(b.old) {
			return -1
		}
		return 1
	})

	return out
}

func rewriteStateFile(statePath string, replacements []rewritePair) error {
	rawState, err := os.ReadFile(statePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read state.json: %w", err)
	}

	rewritten := string(rawState)
	for _, r := range replacements {
		rewritten = strings.ReplaceAll(rewritten, r.old, r.new)
		rewritten = strings.ReplaceAll(
			rewritten,
			strings.ReplaceAll(r.old, "/", "\\/"),
			strings.ReplaceAll(r.new, "/", "\\/"),
		)
	}

	if string(rawState) == rewritten {
		return nil
	}

	return writeRewriteTarget(statePath, []byte(rewritten))
}

func writeRewriteTarget(path string, data []byte) error {
	if err := os.Chmod(path, 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
