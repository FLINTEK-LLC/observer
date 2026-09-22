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

func TestIPInfoEnrich_BasicNoToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("expected no auth header when token is empty")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ip":       "1.2.3.4",
			"hostname": "mail.example.com",
			"city":     "Frankfurt",
			"region":   "Hesse",
			"country":  "DE",
			"org":      "AS24940 Hetzner Online GmbH",
		})
	}))
	defer srv.Close()

	e := NewIPInfo("") // no token
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s: %s", result.Status, result.ErrorMessage)
	}
	if result.Data["city"] != "Frankfurt" {
		t.Errorf("expected city=Frankfurt, got %v", result.Data["city"])
	}
	if result.Data["privacy_available"] != false {
		t.Error("expected privacy_available=false when no token")
	}
}

func TestIPInfoEnrich_WithPrivacy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mytoken" {
			t.Errorf("expected auth header 'Bearer mytoken', got %q", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ip":     "1.2.3.4",
			"city":   "Frankfurt",
			"region": "Hesse",
			"org":    "AS24940 Hetzner Online GmbH",
			"privacy": map[string]any{
				"vpn":     true,
				"proxy":   false,
				"tor":     false,
				"relay":   false,
				"hosting": true,
				"service": "ExpressVPN",
			},
		})
	}))
	defer srv.Close()

	// Legacy token: the lookup API rejects it, so we fall back.
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer lookup.Close()

	e := NewIPInfo("mytoken")
	e.baseURL = srv.URL
	e.lookupURL = lookup.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Errorf("expected ok, got %s", result.Status)
	}
	if result.Data["vpn"] != true {
		t.Error("expected vpn=true")
	}
	if result.Data["anonymous"] != true {
		t.Error("expected anonymous=true derived from vpn")
	}
	if result.Data["service"] != "ExpressVPN" {
		t.Errorf("expected service=ExpressVPN, got %v", result.Data["service"])
	}
	if result.Data["privacy_available"] != true {
		t.Error("expected privacy_available=true")
	}
}

func TestIPInfoEnrich_CoreLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lookup/1.2.3.4" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer mytoken" {
			t.Errorf("expected auth header, got %q", r.Header.Get("Authorization"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"ip":           "1.2.3.4",
			"geo":          map[string]any{"city": "Frankfurt", "region": "Hesse", "country_code": "DE"},
			"as":           map[string]any{"asn": "AS24940", "name": "Hetzner Online GmbH"},
			"is_anonymous": true,
			"is_hosting":   true,
		})
	}))
	defer srv.Close()

	e := NewIPInfo("mytoken")
	e.lookupURL = srv.URL
	e.baseURL = "http://127.0.0.1:0" // must not be used

	result, _ := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if result.Status != "ok" {
		t.Fatalf("expected ok, got %s: %s", result.Status, result.ErrorMessage)
	}
	if result.Data["anonymous"] != true || result.Data["hosting"] != true {
		t.Errorf("expected anonymous and hosting true, got %v", result.Data)
	}
	if _, ok := result.Data["vpn"]; ok {
		t.Error("Core has no per-type breakdown; vpn should be absent, not false")
	}
	if result.Data["country"] != "DE" || result.Data["org"] != "AS24940 Hetzner Online GmbH" {
		t.Errorf("unexpected geo/org: %v / %v", result.Data["country"], result.Data["org"])
	}
	if result.Data["privacy_available"] != true {
		t.Error("expected privacy_available=true")
	}
}

func TestIPInfoEnrich_PlusLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"ip": "1.2.3.4",
			"anonymous": map[string]any{
				"name": "CyberGhost", "is_vpn": true, "is_proxy": false, "is_tor": false, "is_relay": false,
			},
			"is_anonymous": true,
			"is_hosting":   true,
		})
	}))
	defer srv.Close()

	e := NewIPInfo("mytoken")
	e.lookupURL = srv.URL

	result, _ := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if result.Data["vpn"] != true || result.Data["proxy"] != false {
		t.Errorf("expected vpn=true proxy=false, got %v", result.Data)
	}
	if result.Data["service"] != "CyberGhost" {
		t.Errorf("expected service=CyberGhost, got %v", result.Data["service"])
	}
}

func TestIPInfoEnrich_UnsupportedType(t *testing.T) {
	e := NewIPInfo("test-token")
	result, err := e.Enrich(context.Background(), "example.com", detect.TypeDomain)
	if err != ErrUnsupportedType {
		t.Errorf("expected ErrUnsupportedType, got %v", err)
	}
	if result.Status != "unsupported" {
		t.Errorf("expected unsupported, got %s", result.Status)
	}
}

func TestIPInfoEnrich_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	e := NewIPInfo("")
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "1.2.3.4", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "rate_limited" {
		t.Errorf("expected rate_limited, got %s", result.Status)
	}
}
