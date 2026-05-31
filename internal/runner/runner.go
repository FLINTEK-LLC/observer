// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package runner

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/flintek-llc/observer/config"
	"github.com/flintek-llc/observer/internal/detect"
	"github.com/flintek-llc/observer/internal/enricher"
	"github.com/flintek-llc/observer/internal/model"
)

// Run enriches a single observable using all configured sources.
func Run(ctx context.Context, observable string, cfg *config.Config) (*model.EnrichmentResult, error) {
	return RunWithOptions(ctx, observable, cfg, nil, nil)
}

// RunWithOptions allows filtering sources by name and injecting custom enrichers (useful for tests).
func RunWithOptions(
	ctx context.Context,
	observable string,
	cfg *config.Config,
	customEnrichers []enricher.Enricher,
	sources []string,
) (*model.EnrichmentResult, error) {
	oType, err := detect.Detect(observable)
	if err != nil {
		return nil, fmt.Errorf("detect observable: %w", err)
	}

	enrichers := customEnrichers
	if enrichers == nil {
		enrichers = buildEnrichers(cfg)
	}

	// Filter by requested source names, if specified.
	if len(sources) > 0 {
		srcSet := make(map[string]bool, len(sources))
		for _, s := range sources {
			srcSet[strings.ToLower(strings.TrimSpace(s))] = true
		}
		filtered := enrichers[:0]
		for _, e := range enrichers {
			if srcSet[e.Name()] {
				filtered = append(filtered, e)
			}
		}
		enrichers = filtered
	}

	result := &model.EnrichmentResult{
		Observable: observable,
		Type:       string(oType),
		Timestamp:  time.Now().UTC(),
		Sources:    make(map[string]*model.SourceResult, len(enrichers)),
	}

	timeout := time.Duration(cfg.EnricherTimeoutSeconds) * time.Second
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, e := range enrichers {
		// Mark unsupported types immediately without spawning a goroutine.
		if !typeSupported(e.SupportedTypes(), oType) {
			mu.Lock()
			result.Sources[e.Name()] = &model.SourceResult{
				Name:   e.Name(),
				Status: "unsupported",
				Data:   map[string]any{},
			}
			mu.Unlock()
			continue
		}

		wg.Add(1)
		go func(enr enricher.Enricher) {
			defer wg.Done()

			eCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			sr, err := enr.Enrich(eCtx, observable, oType)
			if err != nil && err != enricher.ErrUnsupportedType {
				log.Printf("warn: [%s] enrichment error: %v", enr.Name(), err)
			}
			if sr == nil {
				sr = &model.SourceResult{
					Name:         enr.Name(),
					Status:       "error",
					ErrorMessage: "nil result returned",
					Data:         map[string]any{},
				}
			}

			mu.Lock()
			result.Sources[enr.Name()] = sr
			mu.Unlock()
		}(e)
	}

	wg.Wait()
	return result, nil
}

func typeSupported(supported []detect.ObservableType, t detect.ObservableType) bool {
	for _, s := range supported {
		if s == t {
			return true
		}
	}
	return false
}

func buildEnrichers(cfg *config.Config) []enricher.Enricher {
	// At most six sources; pre-allocate to avoid intermediate growth.
	list := make([]enricher.Enricher, 0, 6)

	if cfg.ShodanAPIKey != "" {
		list = append(list, enricher.NewShodan(cfg.ShodanAPIKey))
	}
	if cfg.VirusTotalAPIKey != "" {
		list = append(list, enricher.NewVirusTotal(cfg.VirusTotalAPIKey))
	}
	if cfg.AbuseIPDBAPIKey != "" {
		list = append(list, enricher.NewAbuseIPDB(cfg.AbuseIPDBAPIKey))
	}
	// WHOIS: always included (no API key needed).
	list = append(list, enricher.NewWHOIS())
	if cfg.OTXAPIKey != "" {
		list = append(list, enricher.NewOTX(cfg.OTXAPIKey))
	}
	// ipinfo: basic geo works without a token.
	list = append(list, enricher.NewIPInfo(cfg.IPInfoToken))

	return list
}
