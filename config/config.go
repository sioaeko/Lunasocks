package config

import (
    "encoding/json"
    "os"
    "time"
)

type Config struct {
    ServerAddr     string        `json:"server_addr"`
    LocalAddr      string        `json:"local_addr"`
    Password       string        `json:"password"`
    Method         string        `json:"method"`
    Timeout        time.Duration `json:"timeout"`
    LogLevel       string        `json:"log_level"`
    EnableUDP      bool          `json:"enable_udp"`
}

func LoadConfig(filename string) (*Config, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    config := &Config{}
    err = decoder.Decode(config)
    if err != nil {
        return nil, err
    }

    // Set default values
    if config.Timeout == 0 {
        config.Timeout = 5 * time.Minute
    }
    if config.LogLevel == "" {
        config.LogLevel = "info"
    }
    if config.Method == "" {
        config.Method = "aes-256-gcm"
    }

    return config, nil
}
