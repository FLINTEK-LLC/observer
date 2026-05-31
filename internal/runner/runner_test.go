// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package runner

import (
	"context"
	"errors"
	"testing"

	"github.com/ctrlaltdean/observer/config"
	"github.com/ctrlaltdean/observer/internal/detect"
	"github.com/ctrlaltdean/observer/internal/enricher"
	"github.com/ctrlaltdean/observer/internal/model"
)

// mockEnricher is a test-only enricher that returns a fixed result or error.
type mockEnricher struct {
	name   string
	types  []detect.ObservableType
	result *model.SourceResult
	err    error
}

func (m *mockEnricher) Name() string                            { return m.name }
func (m *mockEnricher) SupportedTypes() []detect.ObservableType { return m.types }
func (m *mockEnricher) Enrich(_ context.Context, _ string, _ detect.ObservableType) (*model.SourceResult, error) {
	return m.result, m.err
}

func testCfg() *config.Config {
	return &config.Config{EnricherTimeoutSeconds: 15, BulkConcurrency: 5}
}

func TestRunWithOptions_PartialFailure(t *testing.T) {
	ok := &mockEnricher{
		name:  "source-ok",
		types: []detect.ObservableType{detect.TypeIPv4},
		result: &model.SourceResult{
			Name:   "source-ok",
			Status: "ok",
			Data:   map[string]any{"field": "value"},
		},
	}
	bad := &mockEnricher{
		name:   "source-bad",
		types:  []detect.ObservableType{detect.TypeIPv4},
		result: nil,
		err:    errors.New("simulated failure"),
	}

	result, err := RunWithOptions(
		context.Background(),
		"1.2.3.4",
		testCfg(),
		[]enricher.Enricher{ok, bad},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected runner error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Observable != "1.2.3.4" {
		t.Errorf("expected observable=1.2.3.4, got %s", result.Observable)
	}
	if result.Type != string(detect.TypeIPv4) {
		t.Errorf("expected type=IPv4, got %s", result.Type)
	}

	// Both sources should be present.
	if _, ok := result.Sources["source-ok"]; !ok {
		t.Error("expected source-ok in results")
	}
	if _, ok := result.Sources["source-bad"]; !ok {
		t.Error("expected source-bad in results (with error status)")
	}

	// Ok source should have ok status.
	if result.Sources["source-ok"].Status != "ok" {
		t.Errorf("expected source-ok status=ok, got %s", result.Sources["source-ok"].Status)
	}
	// Bad source should have error status (nil result replaced with error result).
	if result.Sources["source-bad"].Status != "error" {
		t.Errorf("expected source-bad status=error, got %s", result.Sources["source-bad"].Status)
	}
}

func TestRunWithOptions_UnsupportedTypeSkipped(t *testing.T) {
	ipOnly := &mockEnricher{
		name:  "ip-only",
		types: []detect.ObservableType{detect.TypeIPv4},
		result: &model.SourceResult{
			Name:   "ip-only",
			Status: "ok",
			Data:   map[string]any{},
		},
	}

	result, err := RunWithOptions(
		context.Background(),
		"example.com", // TypeDomain — not supported by ip-only
		testCfg(),
		[]enricher.Enricher{ipOnly},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sr, ok := result.Sources["ip-only"]
	if !ok {
		t.Fatal("expected ip-only in sources")
	}
	if sr.Status != "unsupported" {
		t.Errorf("expected unsupported, got %s", sr.Status)
	}
}

func TestRunWithOptions_SourceFilter(t *testing.T) {
	a := &mockEnricher{
		name:  "source-a",
		types: []detect.ObservableType{detect.TypeIPv4},
		result: &model.SourceResult{
			Name: "source-a", Status: "ok", Data: map[string]any{},
		},
	}
	b := &mockEnricher{
		name:  "source-b",
		types: []detect.ObservableType{detect.TypeIPv4},
		result: &model.SourceResult{
			Name: "source-b", Status: "ok", Data: map[string]any{},
		},
	}

	result, err := RunWithOptions(
		context.Background(),
		"1.2.3.4",
		testCfg(),
		[]enricher.Enricher{a, b},
		[]string{"source-a"}, // only run source-a
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, present := result.Sources["source-a"]; !present {
		t.Error("expected source-a in results")
	}
	if _, present := result.Sources["source-b"]; present {
		t.Error("expected source-b to be excluded")
	}
}

func TestRun_UnknownObservable(t *testing.T) {
	_, err := Run(context.Background(), "not-valid!!", testCfg())
	if err == nil {
		t.Fatal("expected error for unknown observable type")
	}
}

func TestRunWithOptions_AllRateLimited(t *testing.T) {
	rl := &mockEnricher{
		name:  "rate-limited-source",
		types: []detect.ObservableType{detect.TypeIPv4},
		result: &model.SourceResult{
			Name:         "rate-limited-source",
			Status:       "rate_limited",
			ErrorMessage: "rate limited by rate-limited-source",
			Data:         map[string]any{},
		},
	}

	result, err := RunWithOptions(
		context.Background(),
		"1.2.3.4",
		testCfg(),
		[]enricher.Enricher{rl},
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected runner error: %v", err)
	}

	sr := result.Sources["rate-limited-source"]
	if sr.Status != "rate_limited" {
		t.Errorf("expected rate_limited, got %s", sr.Status)
	}
}
