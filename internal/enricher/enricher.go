// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package enricher

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/flintek-llc/observer/internal/detect"
	"github.com/flintek-llc/observer/internal/model"
)

// ErrUnsupportedType is returned when an enricher is called with a type it does not handle.
var ErrUnsupportedType = errors.New("unsupported observable type")

// Enricher is implemented by every enrichment source.
type Enricher interface {
	Name() string
	SupportedTypes() []detect.ObservableType
	Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error)
}

// sharedHTTPClient is reused by every enricher so connections are pooled across
// sources instead of each constructing its own client. *http.Client is safe for
// concurrent use.
var sharedHTTPClient = &http.Client{Timeout: 10 * time.Second}

// newHTTPClient returns the shared client with a fixed timeout.
func newHTTPClient() *http.Client {
	return sharedHTTPClient
}

// unsupportedResult returns a standard "unsupported" SourceResult.
func unsupportedResult(name string) *model.SourceResult {
	return &model.SourceResult{
		Name:   name,
		Status: "unsupported",
		Data:   map[string]any{},
	}
}

// errResult returns a standard "error" SourceResult.
func errResult(name, msg string) *model.SourceResult {
	return &model.SourceResult{
		Name:         name,
		Status:       "error",
		ErrorMessage: msg,
		Data:         map[string]any{},
	}
}

// rateLimitedResult returns a standard "rate_limited" SourceResult.
func rateLimitedResult(name string) *model.SourceResult {
	return &model.SourceResult{
		Name:         name,
		Status:       "rate_limited",
		ErrorMessage: "rate limited by " + name,
		Data:         map[string]any{},
	}
}

// classifyStatus maps the common HTTP error statuses shared by every source to a
// standard SourceResult: 429 → rate_limited, 5xx → server error, 4xx → client
// error. It returns nil for any status the caller must handle itself (2xx, and
// codes the caller special-cases such as 404 before calling this).
func classifyStatus(name string, code int) *model.SourceResult {
	switch {
	case code == http.StatusTooManyRequests:
		return rateLimitedResult(name)
	case code >= 500:
		return errResult(name, fmt.Sprintf("server error: HTTP %d", code))
	case code >= 400:
		return errResult(name, fmt.Sprintf("client error: HTTP %d", code))
	}
	return nil
}

// sanitizeErr returns err's message with any occurrence of secret redacted.
// Go's net/http client embeds the full request URL in its error strings, so
// sources that pass an API key as a query parameter (e.g. Shodan) would
// otherwise leak the key into SourceResult error messages, server logs, and
// API responses. secret may be empty, in which case the message is unchanged.
func sanitizeErr(err error, secret string) string {
	msg := err.Error()
	if secret != "" {
		msg = strings.ReplaceAll(msg, secret, "***")
	}
	return msg
}

// supportsType is a helper used by all enrichers.
func supportsType(supported []detect.ObservableType, t detect.ObservableType) bool {
	for _, s := range supported {
		if s == t {
			return true
		}
	}
	return false
}
