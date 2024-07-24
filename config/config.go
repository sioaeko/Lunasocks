package config

import (
    "io/ioutil"
    "time"

    "gopkg.in/yaml.v2"
)

type Config struct {
    Address          string        `yaml:"address"`
    Password         string        `yaml:"password"`
    Timeout          time.Duration `yaml:"timeout"`
    RedisAddr        string        `yaml:"redis_address"`
    MetricsAddr      string        `yaml:"metrics_address"`
    RateLimit        float64       `yaml:"rate_limit"`
    RateBurst        int           `yaml:"rate_burst"`
    KeyRotationHours int           `yaml:"key_rotation_hours"`
}

func LoadConfig(filename string) (*Config, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }

    var config Config
    err = yaml.Unmarshal(data, &config)
    if err != nil {
        return nil, err
    }

    return &config, nil
}
