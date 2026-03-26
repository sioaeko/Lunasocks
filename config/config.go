package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ServerAddress string `yaml:"server_address" json:"server_address"`
	Password      string `yaml:"password" json:"password"`
	Method        string `yaml:"method" json:"method"`
	Timeout       int    `yaml:"timeout" json:"timeout"`
	UseTLS        bool   `yaml:"use_tls" json:"use_tls"`
	TLSCertFile   string `yaml:"tls_cert_file" json:"tls_cert_file,omitempty"`
	TLSKeyFile    string `yaml:"tls_key_file" json:"tls_key_file,omitempty"`
}

func (c *Config) GetTimeout() time.Duration {
	if c.Timeout <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.Timeout) * time.Second
}

func (c *Config) Validate() {
	if c.ServerAddress == "" {
		c.ServerAddress = "0.0.0.0:1080"
	}
	if c.Method == "" {
		c.Method = "aes-256-gcm"
	}
	if c.Timeout <= 0 {
		c.Timeout = 30
	}
}

func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	cfg.Validate()
	return &cfg, nil
}
