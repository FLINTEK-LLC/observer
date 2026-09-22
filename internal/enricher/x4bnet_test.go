// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package enricher

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/flintek-llc/observer/internal/detect"
)

// newX4BServer serves fixed lists and counts requests per path. Each test gets
// its own server URL, so the package-level cache never leaks between tests.
func newX4BServer(t *testing.T) (*httptest.Server, map[string]*atomic.Int32) {
	t.Helper()
	hits := map[string]*atomic.Int32{
		"/output/vpn/ipv4.txt": {},
		"/output/vpn/ipv6.txt": {},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := hits[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		c.Add(1)
		if strings.HasSuffix(r.URL.Path, "ipv4.txt") {
			fmt.Fprint(w, "# comment\n\n5.6.7.0/24\n10.0.0.0/8\nnot-a-cidr\n203.0.113.9\n")
		} else {
			fmt.Fprint(w, "2001:db8::/32\n")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

func TestX4BNetEnrich_Match(t *testing.T) {
	srv, _ := newX4BServer(t)
	e := NewX4BNet()
	e.baseURL = srv.URL

	result, err := e.Enrich(context.Background(), "5.6.7.8", detect.TypeIPv4)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "ok" {
		t.Fatalf("expected ok, got %s: %s", result.Status, result.ErrorMessage)
	}
	if result.Data["vpn"] != true || result.Data["matched_cidr"] != "5.6.7.0/24" {
		t.Errorf("expected match on 5.6.7.0/24, got %v", result.Data)
	}
	if result.Data["list_size"] != 3 {
		t.Errorf("expected 3 parsed entries (malformed skipped), got %v", result.Data["list_size"])
	}
}

func TestX4BNetEnrich_BareIPEntry(t *testing.T) {
	srv, _ := newX4BServer(t)
	e := NewX4BNet()
	e.baseURL = srv.URL

	result, _ := e.Enrich(context.Background(), "203.0.113.9", detect.TypeIPv4)
	if result.Data["vpn"] != true {
		t.Errorf("expected bare IP entry to match, got %v", result.Data)
	}
}

func TestX4BNetEnrich_NoMatch(t *testing.T) {
	srv, _ := newX4BServer(t)
	e := NewX4BNet()
	e.baseURL = srv.URL

	result, _ := e.Enrich(context.Background(), "8.8.8.8", detect.TypeIPv4)
	if result.Status != "ok" || result.Data["vpn"] != false {
		t.Errorf("expected ok with vpn=false, got %s %v", result.Status, result.Data)
	}
	if _, ok := result.Data["matched_cidr"]; ok {
		t.Error("matched_cidr should be absent when there is no match")
	}
}

func TestX4BNetEnrich_IPv6UsesIPv6List(t *testing.T) {
	srv, hits := newX4BServer(t)
	e := NewX4BNet()
	e.baseURL = srv.URL

	result, _ := e.Enrich(context.Background(), "2001:db8::1", detect.TypeIPv6)
	if result.Data["vpn"] != true {
		t.Errorf("expected IPv6 match, got %v", result.Data)
	}
	if hits["/output/vpn/ipv4.txt"].Load() != 0 {
		t.Error("IPv6 lookup should not fetch the IPv4 list")
	}
}

func TestX4BNetEnrich_CachesList(t *testing.T) {
	srv, hits := newX4BServer(t)

	for _, ip := range []string{"5.6.7.8", "8.8.8.8", "10.1.2.3"} {
		e := NewX4BNet() // fresh enricher per lookup, as the runner does
		e.baseURL = srv.URL
		if r, _ := e.Enrich(context.Background(), ip, detect.TypeIPv4); r.Status != "ok" {
			t.Fatalf("%s: expected ok, got %s", ip, r.Status)
		}
	}
	if n := hits["/output/vpn/ipv4.txt"].Load(); n != 1 {
		t.Errorf("expected 1 fetch across lookups, got %d", n)
	}
}

func TestX4BNetEnrich_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	e := NewX4BNet()
	e.baseURL = srv.URL

	result, _ := e.Enrich(context.Background(), "5.6.7.8", detect.TypeIPv4)
	if result.Status != "rate_limited" {
		t.Errorf("expected rate_limited, got %s", result.Status)
	}
}

func TestX4BNetEnrich_UnsupportedType(t *testing.T) {
	e := NewX4BNet()
	result, err := e.Enrich(context.Background(), "example.com", detect.TypeDomain)
	if err != ErrUnsupportedType || result.Status != "unsupported" {
		t.Errorf("expected unsupported, got %v / %s", err, result.Status)
	}
}
