// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/flintek-llc/observer/internal/detect"
	"github.com/flintek-llc/observer/internal/model"
)

type ShodanEnricher struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

func NewShodan(apiKey string) *ShodanEnricher {
	return &ShodanEnricher{
		apiKey:  apiKey,
		baseURL: "https://api.shodan.io",
		client:  newHTTPClient(),
	}
}

func (s *ShodanEnricher) Name() string { return "shodan" }

func (s *ShodanEnricher) SupportedTypes() []detect.ObservableType {
	return []detect.ObservableType{detect.TypeIPv4, detect.TypeDomain}
}

func (s *ShodanEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
	if !supportsType(s.SupportedTypes(), oType) {
		return unsupportedResult(s.Name()), ErrUnsupportedType
	}

	ip := observable
	if oType == detect.TypeDomain {
		addrs, err := net.DefaultResolver.LookupHost(ctx, observable)
		if err != nil || len(addrs) == 0 {
			return errResult(s.Name(), fmt.Sprintf("DNS resolution failed: %v", err)), nil
		}
		ip = addrs[0]
	}

	url := fmt.Sprintf("%s/shodan/host/%s?key=%s", s.baseURL, ip, s.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return errResult(s.Name(), fmt.Sprintf("request error: %s", sanitizeErr(err, s.apiKey))), nil
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return errResult(s.Name(), fmt.Sprintf("connection failed: %s", sanitizeErr(err, s.apiKey))), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &model.SourceResult{
			Name:   s.Name(),
			Status: "ok",
			Data:   map[string]any{"found": false},
			RawURL: fmt.Sprintf("https://www.shodan.io/host/%s", ip),
		}, nil
	}
	if sr := classifyStatus(s.Name(), resp.StatusCode); sr != nil {
		return sr, nil
	}
	if resp.StatusCode != http.StatusOK {
		return errResult(s.Name(), fmt.Sprintf("unexpected status: HTTP %d", resp.StatusCode)), nil
	}

	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return errResult(s.Name(), fmt.Sprintf("decode error: %v", err)), nil
	}

	data := map[string]any{"found": true}
	for _, k := range []string{"ip_str", "org", "isp", "asn", "country_name", "city", "region_code", "last_update"} {
		if v, ok := raw[k]; ok && v != nil {
			data[k] = v
		}
	}
	for _, k := range []string{"ports", "hostnames", "tags", "vulns"} {
		if v, ok := raw[k]; ok && v != nil {
			data[k] = v
		}
	}

	return &model.SourceResult{
		Name:   s.Name(),
		Status: "ok",
		Data:   data,
		RawURL: fmt.Sprintf("https://www.shodan.io/host/%s", ip),
	}, nil
}
