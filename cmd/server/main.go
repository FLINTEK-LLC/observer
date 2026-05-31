// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ctrlaltdean/observer/config"
	"github.com/ctrlaltdean/observer/web"
)

// Version is set at build time via -ldflags.
var Version = "dev"

func main() {
	// Parse minimal flags manually to avoid a cobra dependency in the server binary.
	port := ""
	cfgFile := ""

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--port", "-port":
			if i+1 < len(args) {
				port = args[i+1]
				i++
			}
		case "--config", "-config":
			if i+1 < len(args) {
				cfgFile = args[i+1]
				i++
			}
		}
	}

	cfg, err := config.Load(cfgFile)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	if port != "" {
		cfg.Port = port
	}

	if cfg.ObserverAPIKey == "" {
		log.Println("warn: OBSERVER_API_KEY not configured — API auth is disabled")
	}

	// Inject the version into the web package for the health endpoint.
	web.Version = Version

	mux := web.NewMux(cfg)

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("observer-server %s listening on http://localhost%s", Version, addr)
	log.Printf("sources: shodan=%v virustotal=%v abuseipdb=%v whois=always otx=%v ipinfo=always",
		cfg.ShodanAPIKey != "",
		cfg.VirusTotalAPIKey != "",
		cfg.AbuseIPDBAPIKey != "",
		cfg.OTXAPIKey != "",
	)

	// Explicit timeouts guard against slow-client (Slowloris) connection
	// exhaustion. WriteTimeout exceeds the bulk handler's 60s context budget.
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
