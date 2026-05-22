package redirect

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

var ErrConfigNotFound = errors.New("config not found")

const (
	DefaultListenV4   = "127.0.0.1:18080"
	DefaultListenV6   = "[::1]:18080"
	DefaultRedirectV4 = "127.0.0.1:18080"
	DefaultRedirectV6 = "[::1]:18080"
)

type Config struct {
	Proxy ProxyConfig `yaml:"proxy"`
	Rules RulesConfig `yaml:"rules"`
}

type ProxyConfig struct {
	ListenV4   string `yaml:"listen_v4"`
	ListenV6   string `yaml:"listen_v6"`
	RedirectV4 string `yaml:"redirect_v4"`
	RedirectV6 string `yaml:"redirect_v6"`
}

type RulesConfig struct {
	PIDs    []uint32 `yaml:"pids"`
	Comms   []string `yaml:"comms"`
	IPs     []string `yaml:"ips"`
	Domains []string `yaml:"domains"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, ErrConfigNotFound
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse yaml: %w", err)
	}

	return cfg, nil
}

func MergeConfig(cli Config, file Config) Config {
	out := cli

	if file.Proxy.ListenV4 != "" {
		out.Proxy.ListenV4 = file.Proxy.ListenV4
	}
	if file.Proxy.ListenV6 != "" {
		out.Proxy.ListenV6 = file.Proxy.ListenV6
	}
	if file.Proxy.RedirectV4 != "" {
		out.Proxy.RedirectV4 = file.Proxy.RedirectV4
	}
	if file.Proxy.RedirectV6 != "" {
		out.Proxy.RedirectV6 = file.Proxy.RedirectV6
	}

	if len(file.Rules.PIDs) > 0 {
		out.Rules.PIDs = file.Rules.PIDs
	}
	if len(file.Rules.Comms) > 0 {
		out.Rules.Comms = file.Rules.Comms
	}
	if len(file.Rules.IPs) > 0 {
		out.Rules.IPs = file.Rules.IPs
	}
	if len(file.Rules.Domains) > 0 {
		out.Rules.Domains = file.Rules.Domains
	}

	return out
}

func WithDefaults(cfg Config) Config {
	if cfg.Proxy.ListenV4 == "" {
		cfg.Proxy.ListenV4 = DefaultListenV4
	}
	if cfg.Proxy.RedirectV4 == "" {
		cfg.Proxy.RedirectV4 = DefaultRedirectV4
	}

	hasV6 := cfg.Proxy.ListenV6 != "" || cfg.Proxy.RedirectV6 != ""
	if hasV6 {
		if cfg.Proxy.ListenV6 == "" {
			cfg.Proxy.ListenV6 = DefaultListenV6
		}
		if cfg.Proxy.RedirectV6 == "" {
			cfg.Proxy.RedirectV6 = DefaultRedirectV6
		}
	}

	return cfg
}
