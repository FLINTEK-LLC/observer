// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/flintek-llc/observer/config"
	"github.com/flintek-llc/observer/internal/runner"
)

//go:embed static
var staticFS embed.FS

// Version is set by the server binary at startup.
var Version = "dev"

const (
	// maxBulkObservables caps how many observables a single bulk request may
	// contain, bounding memory and the number of queued goroutines.
	maxBulkObservables = 1000
	// maxBulkBodyBytes caps the bulk request body size.
	maxBulkBodyBytes = 1 << 20 // 1 MiB
)

// NewMux builds the fully-configured HTTP mux.
func NewMux(cfg *config.Config) http.Handler {
	mux := http.NewServeMux()

	// All /api/* routes go through the auth middleware.
	apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/health":
			handleHealth(w, r)
		case r.URL.Path == "/api/enrich" && r.Method == http.MethodGet:
			handleEnrich(w, r, cfg)
		case r.URL.Path == "/api/enrich/bulk" && r.Method == http.MethodPost:
			handleBulk(w, r, cfg)
		case r.URL.Path == "/api/sources" && r.Method == http.MethodGet:
			handleSources(w, r, cfg)
		default:
			writeError(w, http.StatusNotFound, "route not found", "NOT_FOUND")
		}
	})

	mux.Handle("/api/", APIKeyMiddleware(cfg.ObserverAPIKey, apiHandler))

	// Static files — always unauthenticated, embedded in the binary.
	staticFiles, _ := fs.Sub(staticFS, "static")
	mux.Handle("/", http.FileServer(http.FS(staticFiles)))

	return mux
}

// ─── /api/health ─────────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": Version,
	})
}

// ─── /api/enrich ─────────────────────────────────────────────────────────────

func handleEnrich(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	q := r.URL.Query().Get("q")
	if q == "" {
		writeError(w, http.StatusBadRequest, "missing query parameter 'q'", "MISSING_PARAM")
		return
	}

	var sources []string
	if s := r.URL.Query().Get("sources"); s != "" {
		for _, src := range strings.Split(s, ",") {
			if trimmed := strings.TrimSpace(src); trimmed != "" {
				sources = append(sources, trimmed)
			}
		}
	}

	timeout := time.Duration(cfg.EnricherTimeoutSeconds+5) * time.Second
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	result, err := runner.RunWithOptions(ctx, q, cfg, nil, sources)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error(), "UNSUPPORTED_TYPE")
		return
	}

	// TODO: history — drop a call to store.Save(result) here when a SQLite store is added

	writeJSON(w, http.StatusOK, result)
}

// ─── /api/enrich/bulk ────────────────────────────────────────────────────────

func handleBulk(w http.ResponseWriter, r *http.Request, cfg *config.Config) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBulkBodyBytes)

	var body struct {
		Observables []string `json:"observables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid or oversized JSON body", "INVALID_BODY")
		return
	}
	if len(body.Observables) == 0 {
		writeError(w, http.StatusBadRequest, "observables array must not be empty", "EMPTY_OBSERVABLES")
		return
	}
	if len(body.Observables) > maxBulkObservables {
		writeError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("too many observables (max %d)", maxBulkObservables), "TOO_MANY_OBSERVABLES")
		return
	}

	type indexedResult struct {
		idx    int
		result any
	}

	results := make([]any, len(body.Observables))
	resultCh := make(chan indexedResult, len(body.Observables))
	sem := make(chan struct{}, cfg.BulkConcurrency)

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	for i, obs := range body.Observables {
		i, obs := i, obs
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res, err := runner.RunWithOptions(ctx, obs, cfg, nil, nil)
			if err != nil {
				resultCh <- indexedResult{i, map[string]any{
					"observable": obs,
					"error":      err.Error(),
				}}
				return
			}
			resultCh <- indexedResult{i, res}
		}()
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for ir := range resultCh {
		results[ir.idx] = ir.result
	}

	// TODO: history — persist bulk results here when store is available

	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(results),
		"results": results,
	})
}

// ─── /api/sources ─────────────────────────────────────────────────────────────

func handleSources(w http.ResponseWriter, _ *http.Request, cfg *config.Config) {
	active := cfg.ActiveSources()

	type sourceInfo struct {
		Name        string `json:"name"`
		Configured  bool   `json:"configured"`
		Description string `json:"description"`
	}

	sources := []sourceInfo{
		{"shodan", active["shodan"], "IP/hostname, open ports, CVEs, tags"},
		{"virustotal", active["virustotal"], "Multi-engine scanning for IPs, domains, URLs, and hashes"},
		{"abuseipdb", active["abuseipdb"], "Community abuse-confidence score for IPs"},
		{"whois", active["whois"], "WHOIS registration data for domains and IPs"},
		{"otx", active["otx"], "AlienVault OTX threat pulse lookup"},
		{"ipinfo", active["ipinfo"], "IP geolocation and VPN/TOR/proxy classification"},
	}

	writeJSON(w, http.StatusOK, map[string]any{"sources": sources})
}
