// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package enricher

import (
	"testing"
)

func TestExtractDomainFromURL(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"https://example.com/path?q=1", "example.com"},
		{"http://sub.example.com", "sub.example.com"},
		{"ftp://files.example.com/pub/file.gz", "files.example.com"},
		{"https://example.com:8443/path", "example.com"},
		{"http://1.2.3.4/admin", "1.2.3.4"},
	}

	for _, tc := range cases {
		got := extractDomainFromURL(tc.input)
		if got != tc.want {
			t.Errorf("extractDomainFromURL(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestWHOISSupportedTypes(t *testing.T) {
	e := NewWHOIS()
	if e.Name() != "whois" {
		t.Errorf("expected name 'whois', got %q", e.Name())
	}
	types := e.SupportedTypes()
	if len(types) == 0 {
		t.Error("expected WHOIS to support at least one type")
	}
}

func TestSetIfNotEmpty(t *testing.T) {
	m := map[string]any{}
	setIfNotEmpty(m, "key1", "value")
	setIfNotEmpty(m, "key2", "")

	if m["key1"] != "value" {
		t.Errorf("expected key1=value, got %v", m["key1"])
	}
	if _, ok := m["key2"]; ok {
		t.Error("expected key2 to not be set")
	}
}
