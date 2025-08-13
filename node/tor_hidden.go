package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// StartTorHiddenService attempts to launch a Tor hidden service that forwards
// a local HTTP port to an onion address. It returns the onion address (e.g.
// abcdefghijklmnop.onion) or an error if it cannot be created.
// listenAddr is the local address the node is listening on, e.g. ":7742".
func StartTorHiddenService(listenAddr string) (string, error) {
	// Base directory for hidden service data
	torBase := filepath.Join("data", "tor_hidden")
	onionDir := filepath.Join(torBase, "onion")

// Ensure tor binary is available
if _, err := exec.LookPath("tor"); err != nil {
		return "", fmt.Errorf("tor binary not found in PATH: %v", err)
}
	// Prepare onion service directory
	if err := os.MkdirAll(onionDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create onion dir: %w", err)
	}

	// torrc path
	torrcPath := filepath.Join(torBase, "torrc")
	if err := os.MkdirAll(filepath.Dir(torrcPath), 0o755); err != nil {
		return "", fmt.Errorf("failed to prepare torrc dir: %w", err)
	}

	// Determine port to forward to (parse listenAddr)
	port := "7742"
	if strings.HasPrefix(listenAddr, ":") && len(listenAddr) > 1 {
		port = listenAddr[1:]
	} else if idx := strings.LastIndex(listenAddr, ":"); idx != -1 && idx < len(listenAddr)-1 {
		port = listenAddr[idx+1:]
	}

	// Write torrc configuration
	// HiddenServiceDir is the directory: onionDir
	// HiddenServicePort maps external onion port 80 to local port
	torrc := fmt.Sprintf("HiddenServiceDir %q\nHiddenServicePort 80 127.0.0.1:%s\n", onionDir, port)
	if err := os.WriteFile(torrcPath, []byte(torrc), 0o600); err != nil {
		return "", fmt.Errorf("failed to write torrc: %w", err)
	}

	// Launch tor with logging
	cmd := exec.Command("tor", "-f", torrcPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Detach from terminal; run in background
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start tor: %w; stdout=%q; stderr=%q", err, stdout.String(), stderr.String())
	}
	// Reap the process in background to avoid zombies
	go func() { _ = cmd.Wait() }()

	// Read hostname from the hidden service after Tor initializes
	hostnamePath := filepath.Join(onionDir, "hostname")
	// Wait for the hostname file to appear (with a generous timeout)
	timeout := time.After(90 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-timeout:
			return "", fmt.Errorf("tor hidden service hostname not available after startup: timeout; stdout=%q; stderr=%q", stdout.String(), stderr.String())
		case <-ticker.C:
			if b, err := os.ReadFile(hostnamePath); err == nil {
				hostname := strings.TrimSpace(string(b))
				if hostname != "" {
					return hostname, nil
				}
			}
		}
	}
}