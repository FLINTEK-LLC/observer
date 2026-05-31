// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package detect

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

// ObservableType identifies what kind of indicator a raw string represents.
type ObservableType string

const (
	TypeIPv4    ObservableType = "IPv4"
	TypeIPv6    ObservableType = "IPv6"
	TypeDomain  ObservableType = "Domain"
	TypeURL     ObservableType = "URL"
	TypeMD5     ObservableType = "MD5"
	TypeSHA1    ObservableType = "SHA1"
	TypeSHA256  ObservableType = "SHA256"
	TypeUnknown ObservableType = "Unknown"
)

// ErrUnknownType is returned when the input cannot be classified.
type UnknownTypeError struct {
	Input string
}

func (e *UnknownTypeError) Error() string {
	return "unknown observable type: " + e.Input
}

// ErrUnknownType is a sentinel for callers that only need an equality check.
var ErrUnknownType = errors.New("unknown observable type")

var (
	reMD5    = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	reSHA1   = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	reSHA256 = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	// FQDN: one or more labels separated by dots, ending with a multi-char TLD.
	reDomain = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// Detect classifies a raw string into an ObservableType.
// Returns (TypeUnknown, *UnknownTypeError) when the type cannot be determined.
func Detect(s string) (ObservableType, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return TypeUnknown, &UnknownTypeError{Input: s}
	}

	// URL: must have a recognised scheme.
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ftp://") {
		return TypeURL, nil
	}

	// IP address (v4 or v6) — net.ParseIP is authoritative.
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return TypeIPv4, nil
		}
		return TypeIPv6, nil
	}

	// Hash types — checked by exact hex-char length before domain so that
	// 32/40/64-char hex strings are never mis-classified as domains.
	if reMD5.MatchString(s) {
		return TypeMD5, nil
	}
	if reSHA1.MatchString(s) {
		return TypeSHA1, nil
	}
	if reSHA256.MatchString(s) {
		return TypeSHA256, nil
	}

	// Domain (FQDN without scheme or path).
	if reDomain.MatchString(s) {
		return TypeDomain, nil
	}

	return TypeUnknown, &UnknownTypeError{Input: s}
}

// IsHash returns true for MD5, SHA1, or SHA256 types.
func IsHash(t ObservableType) bool {
	return t == TypeMD5 || t == TypeSHA1 || t == TypeSHA256
}

// IsIP returns true for IPv4 or IPv6 types.
func IsIP(t ObservableType) bool {
	return t == TypeIPv4 || t == TypeIPv6
}
