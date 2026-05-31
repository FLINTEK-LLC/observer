// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	// Enrichment API keys — empty string means source is disabled.
	ShodanAPIKey     string
	VirusTotalAPIKey string
	AbuseIPDBAPIKey  string
	OTXAPIKey        string
	IPInfoToken      string

	// Server settings
	ObserverAPIKey string
	Port           string
	LogLevel       string

	// Tuning
	EnricherTimeoutSeconds int
	BulkConcurrency        int
}

// Load reads config from an optional .env file and then from environment variables.
// Environment variables always override .env values.
// envFile may be empty, in which case ".env" in the working directory is tried.
func Load(envFile string) (*Config, error) {
	if envFile != "" {
		if err := godotenv.Load(envFile); err != nil {
			log.Printf("warn: could not load env file %s: %v", envFile, err)
		}
	} else {
		// Best-effort: ignore error if .env doesn't exist.
		_ = godotenv.Load()
	}

	return &Config{
		ShodanAPIKey:     os.Getenv("SHODAN_API_KEY"),
		VirusTotalAPIKey: os.Getenv("VIRUSTOTAL_API_KEY"),
		AbuseIPDBAPIKey:  os.Getenv("ABUSEIPDB_API_KEY"),
		OTXAPIKey:        os.Getenv("OTX_API_KEY"),
		IPInfoToken:      os.Getenv("IPINFO_TOKEN"),

		ObserverAPIKey: os.Getenv("OBSERVER_API_KEY"),
		Port:           envOr("OBSERVER_PORT", "8080"),
		LogLevel:       envOr("OBSERVER_LOG_LEVEL", "info"),

		EnricherTimeoutSeconds: envInt("ENRICHER_TIMEOUT_SECONDS", 15),
		BulkConcurrency:        envInt("BULK_CONCURRENCY", 5),
	}, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			log.Printf("warn: invalid integer for %s=%q, using default %d", key, v, def)
			return def
		}
		return n
	}
	return def
}

// ActiveSources returns a map of source name -> whether the source has a key configured.
func (c *Config) ActiveSources() map[string]bool {
	return map[string]bool{
		"shodan":     c.ShodanAPIKey != "",
		"virustotal": c.VirusTotalAPIKey != "",
		"abuseipdb":  c.AbuseIPDBAPIKey != "",
		"whois":      true, // no key required
		"otx":        c.OTXAPIKey != "",
		"ipinfo":     true, // basic works without token
	}
}
