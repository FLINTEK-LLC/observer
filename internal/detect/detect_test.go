// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package detect

import (
	"errors"
	"testing"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected ObservableType
		wantErr  bool
	}{
		// ── IPv4 ──────────────────────────────────────────────────────────────
		{name: "ipv4 simple", input: "1.2.3.4", expected: TypeIPv4},
		{name: "ipv4 private", input: "192.168.1.1", expected: TypeIPv4},
		{name: "ipv4 zeros", input: "0.0.0.0", expected: TypeIPv4},
		{name: "ipv4 broadcast", input: "255.255.255.255", expected: TypeIPv4},
		{name: "ipv4 loopback", input: "127.0.0.1", expected: TypeIPv4},

		// ── IPv6 ──────────────────────────────────────────────────────────────
		{name: "ipv6 full", input: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", expected: TypeIPv6},
		{name: "ipv6 compressed", input: "2001:db8::1", expected: TypeIPv6},
		{name: "ipv6 loopback", input: "::1", expected: TypeIPv6},
		// IPv4-mapped IPv6 address — Go's net.ParseIP treats these as IPv4 (To4() != nil).
		{name: "ipv6 mapped", input: "::ffff:192.0.2.1", expected: TypeIPv4},

		// ── URL ───────────────────────────────────────────────────────────────
		{name: "http url", input: "http://example.com", expected: TypeURL},
		{name: "https url with path", input: "https://example.com/path?q=1#frag", expected: TypeURL},
		{name: "ftp url", input: "ftp://files.example.com/pub/file.tar.gz", expected: TypeURL},
		{name: "https url with ip", input: "https://1.2.3.4/admin", expected: TypeURL},
		{name: "uppercase scheme", input: "HTTP://example.com", expected: TypeURL},

		// ── Domain ────────────────────────────────────────────────────────────
		{name: "simple domain", input: "example.com", expected: TypeDomain},
		{name: "subdomain", input: "sub.example.com", expected: TypeDomain},
		{name: "deep subdomain", input: "a.b.c.example.co.uk", expected: TypeDomain},
		{name: "hyphen domain", input: "my-site.example.com", expected: TypeDomain},
		{name: "single char label", input: "a.example.com", expected: TypeDomain},

		// ── MD5 ───────────────────────────────────────────────────────────────
		{name: "md5 lowercase", input: "d41d8cd98f00b204e9800998ecf8427e", expected: TypeMD5},
		{name: "md5 uppercase", input: "D41D8CD98F00B204E9800998ECF8427E", expected: TypeMD5},
		{name: "md5 mixed case", input: "098F6bcd4621d373cade4e832627b4f6", expected: TypeMD5},

		// ── SHA1 ──────────────────────────────────────────────────────────────
		{name: "sha1", input: "da39a3ee5e6b4b0d3255bfef95601890afd80709", expected: TypeSHA1},
		{name: "sha1 uppercase", input: "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", expected: TypeSHA1},

		// ── SHA256 ────────────────────────────────────────────────────────────
		{
			name:     "sha256",
			input:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			expected: TypeSHA256,
		},

		// ── Unknown / errors ──────────────────────────────────────────────────
		{name: "empty string", input: "", wantErr: true},
		{name: "whitespace only", input: "   ", wantErr: true},
		{name: "bare hostname no dot", input: "localhost", wantErr: true},
		{name: "invalid ip", input: "999.999.999.999", wantErr: true},
		{name: "partial ip", input: "1.2.3", wantErr: true},
		{name: "short hash", input: "deadbeef", wantErr: true},
		{name: "31 hex chars (not md5)", input: "d41d8cd98f00b204e9800998ecf8427", wantErr: true},
		{name: "63 hex chars (not sha256)", input: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85", wantErr: true},
		{name: "random text", input: "hello world", wantErr: true},
		{name: "domain with scheme stripped", input: "example.com/path", wantErr: true}, // has slash — not a clean FQDN
		{name: "ip with port", input: "1.2.3.4:8080", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Detect(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Detect(%q) expected error, got %v (type=%v)", tt.input, got, got)
				}
				return
			}

			if err != nil {
				t.Errorf("Detect(%q) unexpected error: %v", tt.input, err)
				return
			}

			if got != tt.expected {
				t.Errorf("Detect(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestDetectWhitespaceTrimmed(t *testing.T) {
	got, err := Detect("  1.2.3.4  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != TypeIPv4 {
		t.Errorf("expected TypeIPv4, got %v", got)
	}
}

func TestUnknownTypeError(t *testing.T) {
	_, err := Detect("not-valid!!")
	if err == nil {
		t.Fatal("expected error")
	}
	var ute *UnknownTypeError
	if !errors.As(err, &ute) {
		t.Errorf("expected *UnknownTypeError, got %T", err)
	}
}

func TestIsHash(t *testing.T) {
	for _, tc := range []struct {
		t    ObservableType
		want bool
	}{
		{TypeMD5, true}, {TypeSHA1, true}, {TypeSHA256, true},
		{TypeIPv4, false}, {TypeDomain, false}, {TypeURL, false},
	} {
		if got := IsHash(tc.t); got != tc.want {
			t.Errorf("IsHash(%v) = %v, want %v", tc.t, got, tc.want)
		}
	}
}

func TestIsIP(t *testing.T) {
	for _, tc := range []struct {
		t    ObservableType
		want bool
	}{
		{TypeIPv4, true}, {TypeIPv6, true},
		{TypeDomain, false}, {TypeMD5, false}, {TypeURL, false},
	} {
		if got := IsIP(tc.t); got != tc.want {
			t.Errorf("IsIP(%v) = %v, want %v", tc.t, got, tc.want)
		}
	}
}
