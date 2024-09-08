package config

import (
	"embed"
	"encoding/json"
	"fmt"
)

// Embeds the settings.json file within the binary.
// This technique simplifies configuration management by keeping all necessary files within the application binary.

//go:embed settings.json
var embeddedConfig embed.FS

// AppConfig holds application configuration data.
// This structure stores configuration settings required for the application's operation.
type AppConfig struct {
	ServerAddress     string `json:"server_address"`     // Address of the server the application connects to
	ServerPort        string `json:"server_port"`        // Port of the server the application connects to
	ApiKey            string `json:"api_key"`            // AES key for encryption/decryption
	PersistenceOption string `json:"persistence_option"` // Option for maintaining application persistence
	TargetSize        int64  `json:"target_size"`        // Desired size for the application binary
	Method            string `json:"method"`             // Method for custom process or other operations
	URL               string `json:"url"`                // General-purpose URL used by the application
}

// LoadConfig reads the configuration from the embedded JSON file and returns an AppConfig struct.
// This function initializes the application's configuration settings from the embedded file.
func LoadConfig() (*AppConfig, error) {
	// Read the configuration file from the embedded FS
	data, err := embeddedConfig.ReadFile("settings.json")
	if err != nil {
		return nil, fmt.Errorf("error reading embedded configuration file: %w", err)
	}

	// Parse the JSON data into the AppConfig struct
	var config AppConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("error parsing configuration file: %w", err)
	}

	// Validate and set defaults for critical configuration values
	if config.ServerAddress == "" {
		config.ServerAddress = "127.0.0.1" // Default value
	}
	if config.ServerPort == "" {
		config.ServerPort = "8080" // Default value
	}
	if config.ApiKey == "" {
		config.ApiKey = "" // Default value (empty string)
	}
	if config.PersistenceOption == "" {
		config.PersistenceOption = "none" // Default value
	}
	if config.Method == "" {
		config.Method = "0" // Default value (No Custom Process Injection)
	}
	if config.URL == "" {
		config.URL = "" // Default value (empty string)
	}

	return &config, nil
}
