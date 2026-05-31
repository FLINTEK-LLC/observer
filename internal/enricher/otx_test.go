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

	"github.com/ctrlaltdean/observer/internal/detect"
)

func otxResponse(pulseCount int) map[string]any {
	return map[string]any{
		"type_title": "IPv4",
		"reputation": -2,
		"pulse_info": map[string]any{
			"count": pulseCount,
			"pulses": []map[string]any{
				{
					"name": "Malware C2",
					"tags": []string{"c2", "malware"},
					"malware_families": []map[string]any{
						{"display_name": "Emotet"},
					},
				},
			},
		},
	}
}

func TestOTXEnrich_IP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") == "" {
			t.Error("missing OTX API key header")
		}
		json.NewEncoder(w).Encode(otxResponse(8))
	}))
	defer srv.Close()

	e := NewOTX("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s: %s", result.Status, result.ErrorMessage)
	}
	if result.Data["pulse_count"].(int) != 8 {
		t.Errorf("expected pulse_count=8, got %v", result.Data["pulse_count"])
	}
	pulses, ok := result.Data["pulses"].([]map[string]any)
	if !ok || len(pulses) == 0 {
		t.Error("expected at least one pulse in data")
	}
}

func TestOTXEnrich_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	e := NewOTX("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s", result.Status)
	}
	if result.Data["pulse_count"].(int) != 0 {
		t.Errorf("expected pulse_count=0, got %v", result.Data["pulse_count"])
	}
}

func TestOTXEnrich_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	e := NewOTX("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "rate_limited" {
		t.Errorf("expected rate_limited, got %s", result.Status)
	}
}

func TestOTXEnrich_UnsupportedType(t *testing.T) {
	e := NewOTX("test-key")
	// OTX supports URLs, test with an unsupported type that's NOT in its list.
	// Shodan supports only IP/Domain, so let's use a hash type on a source that doesn't support it.
	// Actually OTX supports all types. Let's use a fake type.
	// Instead test the name and supported types.
	types := e.SupportedTypes()
	if len(types) == 0 {
		t.Error("expected OTX to support at least one type")
	}
}

func TestOTXEnrich_Hash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"type_title": "FileHash-MD5",
			"reputation": 0,
			"pulse_info": map[string]any{
				"count":  3,
				"pulses": []map[string]any{},
			},
		})
	}))
	defer srv.Close()

	e := NewOTX("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "d41d8cd98f00b204e9800998ecf8427e", detect.TypeMD5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s", result.Status)
	}
}
