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

func vtResponse(malicious, harmless, undetected int) map[string]any {
	return map[string]any{
		"data": map[string]any{
			"attributes": map[string]any{
				"last_analysis_stats": map[string]any{
					"malicious":  malicious,
					"suspicious": 0,
					"harmless":   harmless,
					"undetected": undetected,
				},
				"last_analysis_date": 1714000000,
				"reputation":         -5,
			},
		},
	}
}

func TestVirusTotalEnrich_IP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(vtResponse(4, 80, 10))
	}))
	defer srv.Close()

	e := NewVirusTotal("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s: %s", result.Status, result.ErrorMessage)
	}
	if result.Data["malicious"] == nil {
		t.Error("expected malicious field in data")
	}
}

func TestVirusTotalEnrich_Domain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(vtResponse(0, 90, 4))
	}))
	defer srv.Close()

	e := NewVirusTotal("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "example.com", detect.TypeDomain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s", result.Status)
	}
}

func TestVirusTotalEnrich_Hash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := vtResponse(20, 60, 14)
		resp["data"].(map[string]any)["attributes"].(map[string]any)["meaningful_name"] = "malware.exe"
		resp["data"].(map[string]any)["attributes"].(map[string]any)["type_description"] = "Win32 EXE"
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	e := NewVirusTotal("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "d41d8cd98f00b204e9800998ecf8427e", detect.TypeMD5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s", result.Status)
	}
	if result.Data["meaningful_name"] != "malware.exe" {
		t.Errorf("expected meaningful_name=malware.exe, got %v", result.Data["meaningful_name"])
	}
}

func TestVirusTotalEnrich_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	e := NewVirusTotal("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "rate_limited" {
		t.Errorf("expected rate_limited, got %s", result.Status)
	}
}

func TestVirusTotalEnrich_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	e := NewVirusTotal("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok for 404, got %s", result.Status)
	}
	if result.Data["found"] != false {
		t.Error("expected found=false")
	}
}
