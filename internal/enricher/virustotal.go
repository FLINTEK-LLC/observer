// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package enricher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ctrlaltdean/observer/internal/detect"
	"github.com/ctrlaltdean/observer/internal/model"
)

type VirusTotalEnricher struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

func NewVirusTotal(apiKey string) *VirusTotalEnricher {
	return &VirusTotalEnricher{
		apiKey:  apiKey,
		baseURL: "https://www.virustotal.com/api/v3",
		client:  newHTTPClient(),
	}
}

func (v *VirusTotalEnricher) Name() string { return "virustotal" }

func (v *VirusTotalEnricher) SupportedTypes() []detect.ObservableType {
	return []detect.ObservableType{
		detect.TypeIPv4, detect.TypeIPv6, detect.TypeDomain, detect.TypeURL,
		detect.TypeMD5, detect.TypeSHA1, detect.TypeSHA256,
	}
}

func (v *VirusTotalEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
	if !supportsType(v.SupportedTypes(), oType) {
		return unsupportedResult(v.Name()), ErrUnsupportedType
	}

	switch oType {
	case detect.TypeIPv4, detect.TypeIPv6:
		return v.enrichIP(ctx, observable)
	case detect.TypeDomain:
		return v.enrichDomain(ctx, observable)
	case detect.TypeURL:
		return v.enrichURL(ctx, observable)
	default:
		return v.enrichFile(ctx, observable)
	}
}

func (v *VirusTotalEnricher) get(ctx context.Context, endpoint string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.baseURL+endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", v.apiKey)
	return v.client.Do(req)
}

func (v *VirusTotalEnricher) enrichIP(ctx context.Context, ip string) (*model.SourceResult, error) {
	resp, err := v.get(ctx, "/ip_addresses/"+ip)
	if err != nil {
		return errResult(v.Name(), fmt.Sprintf("connection failed: %v", err)), nil
	}
	defer resp.Body.Close()
	return v.parseAttributes(resp, fmt.Sprintf("https://www.virustotal.com/gui/ip-address/%s", ip), false)
}

func (v *VirusTotalEnricher) enrichDomain(ctx context.Context, domain string) (*model.SourceResult, error) {
	resp, err := v.get(ctx, "/domains/"+domain)
	if err != nil {
		return errResult(v.Name(), fmt.Sprintf("connection failed: %v", err)), nil
	}
	defer resp.Body.Close()
	return v.parseAttributes(resp, fmt.Sprintf("https://www.virustotal.com/gui/domain/%s", domain), false)
}

func (v *VirusTotalEnricher) enrichFile(ctx context.Context, hash string) (*model.SourceResult, error) {
	resp, err := v.get(ctx, "/files/"+hash)
	if err != nil {
		return errResult(v.Name(), fmt.Sprintf("connection failed: %v", err)), nil
	}
	defer resp.Body.Close()
	return v.parseAttributes(resp, fmt.Sprintf("https://www.virustotal.com/gui/file/%s", hash), true)
}

func (v *VirusTotalEnricher) enrichURL(ctx context.Context, rawURL string) (*model.SourceResult, error) {
	// Try cached result first using base64url-encoded URL (no padding).
	encoded := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(rawURL)), "=")
	resp, err := v.get(ctx, "/urls/"+encoded)
	if err != nil {
		return errResult(v.Name(), fmt.Sprintf("connection failed: %v", err)), nil
	}

	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return v.submitAndPollURL(ctx, rawURL)
	}

	defer resp.Body.Close()
	guiURL := fmt.Sprintf("https://www.virustotal.com/gui/url/%s", encoded)
	return v.parseAttributes(resp, guiURL, false)
}

func (v *VirusTotalEnricher) submitAndPollURL(ctx context.Context, rawURL string) (*model.SourceResult, error) {
	form := url.Values{"url": {rawURL}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.baseURL+"/urls", strings.NewReader(form.Encode()))
	if err != nil {
		return errResult(v.Name(), fmt.Sprintf("submit error: %v", err)), nil
	}
	req.Header.Set("x-apikey", v.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return errResult(v.Name(), fmt.Sprintf("submit failed: %v", err)), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return rateLimitedResult(v.Name()), nil
	}
	if resp.StatusCode >= 400 {
		return errResult(v.Name(), fmt.Sprintf("submit error: HTTP %d", resp.StatusCode)), nil
	}

	var submitResp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&submitResp); err != nil {
		return errResult(v.Name(), fmt.Sprintf("decode submit response: %v", err)), nil
	}

	// Poll up to 3 times, 3s apart.
	for i := 0; i < 3; i++ {
		select {
		case <-ctx.Done():
			return errResult(v.Name(), "context cancelled waiting for analysis"), nil
		case <-time.After(3 * time.Second):
		}

		aResp, err := v.get(ctx, "/analyses/"+submitResp.Data.ID)
		if err != nil {
			return errResult(v.Name(), fmt.Sprintf("poll failed: %v", err)), nil
		}

		var analysisResp struct {
			Data struct {
				Attributes struct {
					Status string         `json:"status"`
					Stats  map[string]any `json:"stats"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := json.NewDecoder(aResp.Body).Decode(&analysisResp); err != nil {
			aResp.Body.Close()
			return errResult(v.Name(), fmt.Sprintf("decode analysis: %v", err)), nil
		}
		aResp.Body.Close()

		if analysisResp.Data.Attributes.Status == "completed" {
			encoded := strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(rawURL)), "=")
			data := map[string]any{}
			if s := analysisResp.Data.Attributes.Stats; s != nil {
				for k, val := range s {
					data[k] = val
				}
			}
			data["analysis_status"] = "completed"
			return &model.SourceResult{
				Name:   v.Name(),
				Status: "ok",
				Data:   data,
				RawURL: fmt.Sprintf("https://www.virustotal.com/gui/url/%s", encoded),
			}, nil
		}
	}

	// Analysis still queued — return partial.
	return &model.SourceResult{
		Name:   v.Name(),
		Status: "ok",
		Data:   map[string]any{"analysis_status": "queued", "note": "analysis submitted but not yet complete"},
	}, nil
}

func (v *VirusTotalEnricher) parseAttributes(resp *http.Response, rawURL string, isFile bool) (*model.SourceResult, error) {
	if resp.StatusCode == http.StatusNotFound {
		return &model.SourceResult{
			Name:   v.Name(),
			Status: "ok",
			Data:   map[string]any{"found": false},
			RawURL: rawURL,
		}, nil
	}
	if sr := classifyStatus(v.Name(), resp.StatusCode); sr != nil {
		return sr, nil
	}

	var envelope struct {
		Data struct {
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return errResult(v.Name(), fmt.Sprintf("decode error: %v", err)), nil
	}

	attrs := envelope.Data.Attributes
	data := map[string]any{"found": true}

	// Flatten last_analysis_stats.
	if stats, ok := attrs["last_analysis_stats"].(map[string]any); ok {
		for k, val := range stats {
			data[k] = val
		}
	}

	for _, k := range []string{"last_analysis_date", "reputation", "tags", "categories"} {
		if val, ok := attrs[k]; ok {
			data[k] = val
		}
	}

	if isFile {
		for _, k := range []string{"meaningful_name", "type_description", "size", "names"} {
			if val, ok := attrs[k]; ok {
				data[k] = val
			}
		}
	}

	return &model.SourceResult{
		Name:   v.Name(),
		Status: "ok",
		Data:   data,
		RawURL: rawURL,
	}, nil
}
