// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/flintek-llc/observer/internal/detect"
	"github.com/flintek-llc/observer/internal/model"
)

// IPInfoEnricher queries ipinfo.io. Anonymization data is exposed differently
// depending on the account's plan:
//
//   - Core/Plus (current plans): api.ipinfo.io/lookup/{ip} returns top-level
//     is_anonymous / is_hosting flags; Plus adds an "anonymous" object with
//     is_vpn / is_proxy / is_tor / is_relay and the service name.
//   - Legacy Business/Privacy plans: ipinfo.io/{ip}/json returns a "privacy"
//     object with vpn / proxy / tor / relay / hosting / service.
//
// With a token we try the lookup API first and fall back to the legacy
// endpoint when the plan doesn't include it (Lite and legacy tokens).
type IPInfoEnricher struct {
	token     string
	baseURL   string // legacy API
	lookupURL string // Core/Plus API
	client    *http.Client
}

func NewIPInfo(token string) *IPInfoEnricher {
	return &IPInfoEnricher{
		token:     token,
		baseURL:   "https://ipinfo.io",
		lookupURL: "https://api.ipinfo.io",
		client:    newHTTPClient(),
	}
}

func (i *IPInfoEnricher) Name() string { return "ipinfo" }

func (i *IPInfoEnricher) SupportedTypes() []detect.ObservableType {
	return []detect.ObservableType{detect.TypeIPv4, detect.TypeIPv6}
}

func (i *IPInfoEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
	if !supportsType(i.SupportedTypes(), oType) {
		return unsupportedResult(i.Name()), ErrUnsupportedType
	}

	if i.token != "" {
		data, status, sr := i.fetchLookup(ctx, observable)
		if sr != nil {
			return sr, nil
		}
		// 401/403/404 mean the token's plan doesn't cover the lookup API.
		if status != http.StatusUnauthorized && status != http.StatusForbidden && status != http.StatusNotFound {
			return i.okResult(observable, data), nil
		}
	}

	data, sr := i.fetchLegacy(ctx, observable)
	if sr != nil {
		return sr, nil
	}
	return i.okResult(observable, data), nil
}

func (i *IPInfoEnricher) okResult(observable string, data map[string]any) *model.SourceResult {
	return &model.SourceResult{
		Name:   i.Name(),
		Status: "ok",
		Data:   data,
		RawURL: fmt.Sprintf("https://ipinfo.io/%s", observable),
	}
}

func (i *IPInfoEnricher) get(ctx context.Context, endpoint string) (*http.Response, *model.SourceResult) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, errResult(i.Name(), fmt.Sprintf("request error: %v", err))
	}
	if i.token != "" {
		req.Header.Set("Authorization", "Bearer "+i.token)
	}
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, errResult(i.Name(), fmt.Sprintf("connection failed: %v", sanitizeErr(err, i.token)))
	}
	return resp, nil
}

// fetchLookup queries the Core/Plus lookup API. When the plan doesn't allow
// it, it returns the HTTP status with nil data and nil result so the caller
// can fall back to the legacy endpoint.
func (i *IPInfoEnricher) fetchLookup(ctx context.Context, observable string) (map[string]any, int, *model.SourceResult) {
	resp, sr := i.get(ctx, fmt.Sprintf("%s/lookup/%s", i.lookupURL, observable))
	if sr != nil {
		return nil, 0, sr
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return nil, resp.StatusCode, nil
	}
	if sr := classifyStatus(i.Name(), resp.StatusCode); sr != nil {
		return nil, resp.StatusCode, sr
	}

	var raw struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		Geo      struct {
			City        string `json:"city"`
			Region      string `json:"region"`
			CountryCode string `json:"country_code"`
		} `json:"geo"`
		AS struct {
			ASN  string `json:"asn"`
			Name string `json:"name"`
		} `json:"as"`
		Anonymous *struct {
			Name    string `json:"name"`
			IsProxy bool   `json:"is_proxy"`
			IsRelay bool   `json:"is_relay"`
			IsTor   bool   `json:"is_tor"`
			IsVPN   bool   `json:"is_vpn"`
		} `json:"anonymous"`
		IsAnonymous *bool `json:"is_anonymous"`
		IsHosting   *bool `json:"is_hosting"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, resp.StatusCode, errResult(i.Name(), fmt.Sprintf("decode error: %v", err))
	}

	data := map[string]any{
		"ip":       raw.IP,
		"hostname": raw.Hostname,
		"city":     raw.Geo.City,
		"region":   raw.Geo.Region,
		"country":  raw.Geo.CountryCode,
		"org":      strings.TrimSpace(raw.AS.ASN + " " + raw.AS.Name),
	}
	if raw.IsHosting != nil {
		data["hosting"] = *raw.IsHosting
	}
	if raw.IsAnonymous != nil {
		data["anonymous"] = *raw.IsAnonymous
	}
	if a := raw.Anonymous; a != nil {
		// Plus: full breakdown by anonymization type.
		data["vpn"] = a.IsVPN
		data["proxy"] = a.IsProxy
		data["tor"] = a.IsTor
		data["relay"] = a.IsRelay
		data["service"] = a.Name
	}
	data["privacy_available"] = raw.IsAnonymous != nil || raw.Anonymous != nil
	if !data["privacy_available"].(bool) {
		data["privacy_note"] = "ipinfo plan does not include privacy data"
	}
	return data, resp.StatusCode, nil
}

// fetchLegacy queries the legacy ipinfo.io/{ip}/json endpoint.
func (i *IPInfoEnricher) fetchLegacy(ctx context.Context, observable string) (map[string]any, *model.SourceResult) {
	resp, sr := i.get(ctx, fmt.Sprintf("%s/%s/json", i.baseURL, observable))
	if sr != nil {
		return nil, sr
	}
	defer resp.Body.Close()

	if sr := classifyStatus(i.Name(), resp.StatusCode); sr != nil {
		return nil, sr
	}

	var raw struct {
		IP       string `json:"ip"`
		Hostname string `json:"hostname"`
		City     string `json:"city"`
		Region   string `json:"region"`
		Country  string `json:"country"`
		Org      string `json:"org"`
		Privacy  *struct {
			VPN     bool   `json:"vpn"`
			Proxy   bool   `json:"proxy"`
			Tor     bool   `json:"tor"`
			Relay   bool   `json:"relay"`
			Hosting bool   `json:"hosting"`
			Service string `json:"service"`
		} `json:"privacy"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, errResult(i.Name(), fmt.Sprintf("decode error: %v", err))
	}

	data := map[string]any{
		"ip":       raw.IP,
		"hostname": raw.Hostname,
		"city":     raw.City,
		"region":   raw.Region,
		"country":  raw.Country,
		"org":      raw.Org,
	}

	if p := raw.Privacy; p != nil {
		data["vpn"] = p.VPN
		data["proxy"] = p.Proxy
		data["tor"] = p.Tor
		data["relay"] = p.Relay
		data["hosting"] = p.Hosting
		data["service"] = p.Service
		data["anonymous"] = p.VPN || p.Proxy || p.Tor || p.Relay
		data["privacy_available"] = true
	} else {
		data["privacy_available"] = false
		if i.token == "" {
			data["privacy_note"] = "privacy data requires ipinfo token"
		} else {
			data["privacy_note"] = "ipinfo plan does not include privacy data"
		}
	}
	return data, nil
}
