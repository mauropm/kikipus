package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	ReadOnly  bool
	Project   string
	Organization string
	Folder    string
	Verbose   bool
	JSON      bool
	CSV       bool
	Markdown  bool
	NoCache   bool
}

func Load() (*Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("toml")
	
	// Add config paths
	home := os.Getenv("HOME")
	if home != "" {
		v.AddConfigPath(filepath.Join(home, ".config", "kikipus"))
	}
	v.AddConfigPath(".")

	v.SetEnvPrefix("kikipus")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Try to read config, but don't fail if it doesn't exist
	if err := v.ReadInConfig(); err != nil {
		// Config doesn't exist - that's fine
	}

	cfg := &Config{
		ReadOnly:     v.GetBool("read-only"),
		Project:      v.GetString("project"),
		Organization: v.GetString("organization"),
		Folder:       v.GetString("folder"),
		Verbose:      v.GetBool("verbose"),
		JSON:         v.GetBool("json"),
		CSV:          v.GetBool("csv"),
		Markdown:     v.GetBool("markdown"),
		NoCache:      v.GetBool("no-cache"),
	}

	return cfg, nil
}

func DefaultConfig() *Config {
	return &Config{
		ReadOnly: true,
	}
}