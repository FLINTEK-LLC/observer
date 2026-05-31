// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package enricher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/flintek-llc/observer/internal/detect"
)

func TestAbuseIPDBEnrich_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Key") == "" {
			t.Error("missing API key header")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"ipAddress":            "1.2.3.4",
				"abuseConfidenceScore": 87,
				"totalReports":         142,
				"numDistinctUsers":     38,
				"lastReportedAt":       "2025-04-28T10:00:00+00:00",
				"usageType":            "Data Center/Web Hosting",
				"isp":                  "Test ISP",
				"domain":               "testdomain.com",
				"countryCode":          "DE",
				"isWhitelisted":        false,
				"isPublic":             true,
			},
		})
	}))
	defer srv.Close()

	e := NewAbuseIPDB("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s: %s", result.Status, result.ErrorMessage)
	}

	score, _ := result.Data["abuse_confidence_score"].(int)
	if score != 87 {
		t.Errorf("expected score=87, got %v", result.Data["abuse_confidence_score"])
	}
	reports, _ := result.Data["total_reports"].(int)
	if reports != 142 {
		t.Errorf("expected reports=142, got %v", result.Data["total_reports"])
	}
}

func TestAbuseIPDBEnrich_UnsupportedType(t *testing.T) {
	e := NewAbuseIPDB("test-key")
	result, err := e.Enrich(context.Background(), "example.com", detect.TypeDomain)
	if err != ErrUnsupportedType {
		t.Errorf("expected ErrUnsupportedType, got %v", err)
	}
	if result.Status != "unsupported" {
		t.Errorf("expected unsupported, got %s", result.Status)
	}
}

func TestAbuseIPDBEnrich_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	e := NewAbuseIPDB("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "rate_limited" {
		t.Errorf("expected rate_limited, got %s", result.Status)
	}
}

func TestAbuseIPDBEnrich_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := NewAbuseIPDB("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}
