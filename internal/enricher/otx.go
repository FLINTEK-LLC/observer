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

type OTXEnricher struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

func NewOTX(apiKey string) *OTXEnricher {
	return &OTXEnricher{
		apiKey:  apiKey,
		baseURL: "https://otx.alienvault.com/api/v1",
		client:  newHTTPClient(),
	}
}

func (o *OTXEnricher) Name() string { return "otx" }

func (o *OTXEnricher) SupportedTypes() []detect.ObservableType {
	return []detect.ObservableType{
		detect.TypeIPv4, detect.TypeIPv6, detect.TypeDomain,
		detect.TypeURL, detect.TypeMD5, detect.TypeSHA1, detect.TypeSHA256,
	}
}

func (o *OTXEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
	if !supportsType(o.SupportedTypes(), oType) {
		return unsupportedResult(o.Name()), ErrUnsupportedType
	}

	var endpoint string
	switch oType {
	case detect.TypeIPv4:
		endpoint = fmt.Sprintf("/indicators/IPv4/%s/general", observable)
	case detect.TypeIPv6:
		endpoint = fmt.Sprintf("/indicators/IPv6/%s/general", observable)
	case detect.TypeDomain:
		endpoint = fmt.Sprintf("/indicators/domain/%s/general", observable)
	case detect.TypeURL:
		endpoint = fmt.Sprintf("/indicators/url/%s/general", url.PathEscape(observable))
	default:
		endpoint = fmt.Sprintf("/indicators/file/%s/general", observable)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.baseURL+endpoint, nil)
	if err != nil {
		return errResult(o.Name(), fmt.Sprintf("request error: %v", err)), nil
	}
	req.Header.Set("X-OTX-API-KEY", o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return errResult(o.Name(), fmt.Sprintf("connection failed: %v", err)), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &model.SourceResult{
			Name:   o.Name(),
			Status: "ok",
			Data:   map[string]any{"pulse_count": 0},
		}, nil
	}
	if sr := classifyStatus(o.Name(), resp.StatusCode); sr != nil {
		return sr, nil
	}

	var raw struct {
		TypeTitle  string `json:"type_title"`
		Reputation int    `json:"reputation"`
		PulseInfo  struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name            string   `json:"name"`
				Tags            []string `json:"tags"`
				MalwareFamilies []struct {
					DisplayName string `json:"display_name"`
				} `json:"malware_families"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return errResult(o.Name(), fmt.Sprintf("decode error: %v", err)), nil
	}

	data := map[string]any{
		"pulse_count": raw.PulseInfo.Count,
		"type_title":  raw.TypeTitle,
		"reputation":  raw.Reputation,
	}

	// Collect up to 5 pulses.
	limit := 5
	if len(raw.PulseInfo.Pulses) < limit {
		limit = len(raw.PulseInfo.Pulses)
	}
	pulses := make([]map[string]any, 0, limit)
	for i := 0; i < limit; i++ {
		p := raw.PulseInfo.Pulses[i]
		families := make([]string, 0, len(p.MalwareFamilies))
		for _, mf := range p.MalwareFamilies {
			families = append(families, mf.DisplayName)
		}
		pulses = append(pulses, map[string]any{
			"name":             p.Name,
			"tags":             p.Tags,
			"malware_families": families,
		})
	}
	if len(pulses) > 0 {
		data["pulses"] = pulses
	}

	guiURL := fmt.Sprintf("https://otx.alienvault.com/indicator/%s/%s", otxIndicatorType(oType), url.PathEscape(observable))
	return &model.SourceResult{
		Name:   o.Name(),
		Status: "ok",
		Data:   data,
		RawURL: guiURL,
	}, nil
}

func otxIndicatorType(t detect.ObservableType) string {
	switch t {
	case detect.TypeIPv4, detect.TypeIPv6:
		return "ip"
	case detect.TypeDomain:
		return "domain"
	case detect.TypeURL:
		return "url"
	default:
		return "file"
	}
}
