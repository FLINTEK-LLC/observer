// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package model

import "time"

// EnrichmentResult is the top-level result returned by the runner for a single observable.
type EnrichmentResult struct {
	Observable string                   `json:"observable"`
	Type       string                   `json:"type"`
	Timestamp  time.Time                `json:"timestamp"`
	Sources    map[string]*SourceResult `json:"sources"`
}

// SourceResult holds the normalised output from one enrichment source.
type SourceResult struct {
	Name         string         `json:"name"`
	Status       string         `json:"status"` // "ok" | "error" | "rate_limited" | "unsupported"
	ErrorMessage string         `json:"error_message,omitempty"`
	Data         map[string]any `json:"data"`
	RawURL       string         `json:"raw_url,omitempty"`
}
