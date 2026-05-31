// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ctrlaltdean/observer/internal/detect"
	"github.com/ctrlaltdean/observer/internal/model"
)

type AbuseIPDBEnricher struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

func NewAbuseIPDB(apiKey string) *AbuseIPDBEnricher {
	return &AbuseIPDBEnricher{
		apiKey:  apiKey,
		baseURL: "https://api.abuseipdb.com/api/v2",
		client:  newHTTPClient(),
	}
}

func (a *AbuseIPDBEnricher) Name() string { return "abuseipdb" }

func (a *AbuseIPDBEnricher) SupportedTypes() []detect.ObservableType {
	return []detect.ObservableType{detect.TypeIPv4, detect.TypeIPv6}
}

func (a *AbuseIPDBEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
	if !supportsType(a.SupportedTypes(), oType) {
		return unsupportedResult(a.Name()), ErrUnsupportedType
	}

	params := url.Values{
		"ipAddress":    {observable},
		"maxAgeInDays": {"90"},
		"verbose":      {""},
	}

	endpoint := fmt.Sprintf("%s/check?%s", a.baseURL, params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errResult(a.Name(), fmt.Sprintf("request error: %v", err)), nil
	}
	req.Header.Set("Key", a.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return errResult(a.Name(), fmt.Sprintf("connection failed: %v", err)), nil
	}
	defer resp.Body.Close()

	if sr := classifyStatus(a.Name(), resp.StatusCode); sr != nil {
		return sr, nil
	}

	var envelope struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
			NumDistinctUsers     int    `json:"numDistinctUsers"`
			LastReportedAt       string `json:"lastReportedAt"`
			UsageType            string `json:"usageType"`
			ISP                  string `json:"isp"`
			Domain               string `json:"domain"`
			CountryCode          string `json:"countryCode"`
			IsWhitelisted        bool   `json:"isWhitelisted"`
			IsPublic             bool   `json:"isPublic"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return errResult(a.Name(), fmt.Sprintf("decode error: %v", err)), nil
	}

	d := envelope.Data
	data := map[string]any{
		"abuse_confidence_score": d.AbuseConfidenceScore,
		"total_reports":          d.TotalReports,
		"num_distinct_users":     d.NumDistinctUsers,
		"last_reported_at":       d.LastReportedAt,
		"usage_type":             d.UsageType,
		"isp":                    d.ISP,
		"domain":                 d.Domain,
		"country_code":           d.CountryCode,
		"is_whitelisted":         d.IsWhitelisted,
		"is_public":              d.IsPublic,
	}

	return &model.SourceResult{
		Name:   a.Name(),
		Status: "ok",
		Data:   data,
		RawURL: fmt.Sprintf("https://www.abuseipdb.com/check/%s", observable),
	}, nil
}
