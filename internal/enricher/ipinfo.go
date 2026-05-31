// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ctrlaltdean/observer/internal/detect"
	"github.com/ctrlaltdean/observer/internal/model"
)

type IPInfoEnricher struct {
	token   string
	baseURL string
	client  *http.Client
}

func NewIPInfo(token string) *IPInfoEnricher {
	return &IPInfoEnricher{
		token:   token,
		baseURL: "https://ipinfo.io",
		client:  newHTTPClient(),
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

	endpoint := fmt.Sprintf("%s/%s/json", i.baseURL, observable)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return errResult(i.Name(), fmt.Sprintf("request error: %v", err)), nil
	}
	if i.token != "" {
		req.Header.Set("Authorization", "Bearer "+i.token)
	}

	resp, err := i.client.Do(req)
	if err != nil {
		return errResult(i.Name(), fmt.Sprintf("connection failed: %v", err)), nil
	}
	defer resp.Body.Close()

	if sr := classifyStatus(i.Name(), resp.StatusCode); sr != nil {
		return sr, nil
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
		return errResult(i.Name(), fmt.Sprintf("decode error: %v", err)), nil
	}

	data := map[string]any{
		"ip":       raw.IP,
		"hostname": raw.Hostname,
		"city":     raw.City,
		"region":   raw.Region,
		"country":  raw.Country,
		"org":      raw.Org,
	}

	if raw.Privacy != nil {
		data["vpn"] = raw.Privacy.VPN
		data["proxy"] = raw.Privacy.Proxy
		data["tor"] = raw.Privacy.Tor
		data["relay"] = raw.Privacy.Relay
		data["hosting"] = raw.Privacy.Hosting
		data["service"] = raw.Privacy.Service
		data["privacy_available"] = true
	} else {
		data["privacy_available"] = false
		data["privacy_note"] = "privacy data requires ipinfo token"
	}

	return &model.SourceResult{
		Name:   i.Name(),
		Status: "ok",
		Data:   data,
		RawURL: fmt.Sprintf("https://ipinfo.io/%s", observable),
	}, nil
}
