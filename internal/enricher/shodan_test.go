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

func TestShodanEnrich_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") == "" {
			t.Error("missing API key in request")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ip_str":       "1.2.3.4",
			"org":          "Test Org",
			"isp":          "Test ISP",
			"asn":          "AS12345",
			"country_name": "Germany",
			"city":         "Frankfurt",
			"region_code":  "HE",
			"ports":        []int{22, 80, 443},
			"hostnames":    []string{"mail.example.com"},
			"tags":         []string{"vpn"},
		})
	}))
	defer srv.Close()

	e := NewShodan("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected status ok, got %s", result.Status)
	}
	if result.Data["org"] != "Test Org" {
		t.Errorf("expected org 'Test Org', got %v", result.Data["org"])
	}
	if result.Data["found"] != true {
		t.Error("expected found=true")
	}
}

func TestShodanEnrich_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	e := NewShodan("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected status ok for 404, got %s", result.Status)
	}
	if result.Data["found"] != false {
		t.Error("expected found=false")
	}
}

func TestShodanEnrich_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	e := NewShodan("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "rate_limited" {
		t.Errorf("expected rate_limited, got %s", result.Status)
	}
}

func TestShodanEnrich_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	e := NewShodan("test-key")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestShodanEnrich_UnsupportedType(t *testing.T) {
	e := NewShodan("test-key")
	result, err := e.Enrich(context.Background(), "deadbeef", detect.TypeMD5)
	if err != ErrUnsupportedType {
		t.Errorf("expected ErrUnsupportedType, got %v", err)
	}
	if result.Status != "unsupported" {
		t.Errorf("expected unsupported, got %s", result.Status)
	}
}
