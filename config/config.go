package config

import (
    "gopkg.in/yaml.v2"
    "io/ioutil"
)

type Config struct {
    ServerAddress string `yaml:"server_address"`
    Password      string `yaml:"password"`
    UseTLS        bool   `yaml:"use_tls"`
    TLSCertFile   string `yaml:"tls_cert_file"`
    TLSKeyFile    string `yaml:"tls_key_file"`
    // 추가 설정 필드
}

func LoadConfig(filename string) (*Config, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }

    var cfg Config
    err = yaml.Unmarshal(data, &cfg)
    if err != nil {
        return nil, err
    }

    return &cfg, nil
}
