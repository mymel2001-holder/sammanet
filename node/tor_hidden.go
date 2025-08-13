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
	// Compute absolute tor data paths
	cwd, _ := os.Getwd()
	torBaseAbs := filepath.Join(cwd, "data", "tor_hidden")
	onionDirAbs := filepath.Join(torBaseAbs, "onion")

	// Ensure tor binary is available
	if _, err := exec.LookPath("tor"); err != nil {
		return "", fmt.Errorf("tor binary not found in PATH: %v", err)
	}

	// Prepare onion service directory with secure permissions
	if err := os.MkdirAll(onionDirAbs, 0o700); err != nil {
		return "", fmt.Errorf("failed to create onion dir: %w", err)
	}

	// torrc path
	torrcPathAbs := filepath.Join(torBaseAbs, "torrc")
	if err := os.MkdirAll(filepath.Dir(torrcPathAbs), 0o700); err != nil {
		return "", fmt.Errorf("failed to prepare torrc dir: %w", err)
	}

	// Determine port to forward to (parse listenAddr)
	port := "7742"
	if strings.HasPrefix(listenAddr, ":") && len(listenAddr) > 1 {
		port = listenAddr[1:]
	} else if idx := strings.LastIndex(listenAddr, ":"); idx != -1 && idx < len(listenAddr)-1 {
		port = listenAddr[idx+1:]
	}

	// torrc content
	torrc := fmt.Sprintf("HiddenServiceDir %q\nHiddenServicePort 80 127.0.0.1:%s\n", onionDirAbs, port)

	// Try to use the system default Tor config if possible
	defaultTorrcs := []string{"/etc/tor/torrc", "/usr/local/etc/tor/torrc"}
	useDefault := false
	for _, p := range defaultTorrcs {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			// Append with a comment for traceability
			_, err2 := f.WriteString("\n# Sammanet appended hidden service config\n" + torrc)
			f.Close()
			if err2 == nil {
				useDefault = true
				break
			}
		}
	}

	var cmd *exec.Cmd
	var stdout, stderr bytes.Buffer

	if useDefault {
		// Use default system tor config (no -f)
		cmd = exec.Command("tor")
	} else {
		// Fall back to local torrc
		if err := os.WriteFile(torrcPathAbs, []byte(torrc), 0o600); err != nil {
			return "", fmt.Errorf("failed to write torrc: %w", err)
		}
		cmd = exec.Command("tor", "-f", torrcPathAbs)
	}

	// Launch tor with logging
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Detach from terminal; run in background
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start tor: %w; stdout=%q; stderr=%q", err, stdout.String(), stderr.String())
	}
	// Reap the process in background to avoid zombies
	go func() { _ = cmd.Wait() }()

	// Read hostname from the hidden service after Tor initializes
	hostnamePath := filepath.Join(onionDirAbs, "hostname")
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