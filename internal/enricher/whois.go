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
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"

	"github.com/flintek-llc/observer/internal/detect"
	"github.com/flintek-llc/observer/internal/model"
)

type WHOISEnricher struct {
	rdapBaseURL string
	client      *http.Client
}

func NewWHOIS() *WHOISEnricher {
	return &WHOISEnricher{
		rdapBaseURL: "https://rdap.arin.net/registry",
		client:      newHTTPClient(),
	}
}

func (w *WHOISEnricher) Name() string { return "whois" }

func (w *WHOISEnricher) SupportedTypes() []detect.ObservableType {
	return []detect.ObservableType{
		detect.TypeIPv4, detect.TypeIPv6, detect.TypeDomain, detect.TypeURL,
	}
}

func (w *WHOISEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
	if !supportsType(w.SupportedTypes(), oType) {
		return unsupportedResult(w.Name()), ErrUnsupportedType
	}

	switch oType {
	case detect.TypeIPv4, detect.TypeIPv6:
		return w.enrichIP(ctx, observable)
	case detect.TypeDomain:
		return w.enrichDomain(ctx, observable)
	case detect.TypeURL:
		domain := extractDomainFromURL(observable)
		if domain == "" {
			return errResult(w.Name(), "could not extract domain from URL"), nil
		}
		return w.enrichDomain(ctx, domain)
	default:
		return unsupportedResult(w.Name()), ErrUnsupportedType
	}
}

// ─── IP enrichment via RDAP ───────────────────────────────────────────────────

// rdapNetwork is the RDAP IP network object returned by any RIR.
type rdapNetwork struct {
	Name         string       `json:"name"`
	Country      string       `json:"country"`
	StartAddress string       `json:"startAddress"`
	EndAddress   string       `json:"endAddress"`
	Entities     []rdapEntity `json:"entities"`
	Events       []rdapEvent  `json:"events"`
	Links        []rdapLink   `json:"links"`
	Cidrs        []rdapCIDR   `json:"cidr0_cidrs"`
}

type rdapEntity struct {
	Handle     string       `json:"handle"`
	Roles      []string     `json:"roles"`
	VcardArray []any        `json:"vcardArray"`
	Entities   []rdapEntity `json:"entities"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type rdapCIDR struct {
	V4Prefix string `json:"v4prefix"`
	V6Prefix string `json:"v6prefix"`
	Length   int    `json:"length"`
}

func (w *WHOISEnricher) enrichIP(ctx context.Context, ip string) (*model.SourceResult, error) {
	data := map[string]any{}

	// rDNS lookup.
	ptrs, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err == nil && len(ptrs) > 0 {
		clean := make([]string, len(ptrs))
		for i, p := range ptrs {
			clean[i] = strings.TrimSuffix(p, ".")
		}
		data["ptr_records"] = clean
	}

	// RDAP returns structured JSON — arin.net bootstraps and redirects to the
	// correct RIR (RIPE, APNIC, LACNIC, AFRINIC) automatically.
	rdapURL := fmt.Sprintf("%s/ip/%s", w.rdapBaseURL, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapURL, nil)
	if err != nil {
		return partialOrErr(w.Name(), data, "RDAP request error: "+err.Error())
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := w.client.Do(req)
	if err != nil {
		return partialOrErr(w.Name(), data, "RDAP query failed: "+err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return partialOrErr(w.Name(), data, fmt.Sprintf("RDAP returned HTTP %d", resp.StatusCode))
	}

	var network rdapNetwork
	if err := json.NewDecoder(resp.Body).Decode(&network); err != nil {
		return partialOrErr(w.Name(), data, "RDAP decode error: "+err.Error())
	}

	parseRDAPNetwork(&network, data)

	// If RDAP gave us nothing useful and we also have no PTR, say so.
	if len(data) == 0 {
		return errResult(w.Name(), "no data returned from RDAP"), nil
	}

	return &model.SourceResult{
		Name:   w.Name(),
		Status: "ok",
		Data:   data,
		RawURL: fmt.Sprintf("https://search.arin.net/rdap/?query=%s", ip),
	}, nil
}

func parseRDAPNetwork(n *rdapNetwork, data map[string]any) {
	if n.Name != "" {
		data["network_name"] = n.Name
	}
	if n.Country != "" {
		data["country"] = n.Country
	}

	// Prefer CIDR notation; fall back to address range.
	if len(n.Cidrs) > 0 {
		c := n.Cidrs[0]
		if c.V4Prefix != "" {
			data["cidr"] = fmt.Sprintf("%s/%d", c.V4Prefix, c.Length)
		} else if c.V6Prefix != "" {
			data["cidr"] = fmt.Sprintf("%s/%d", c.V6Prefix, c.Length)
		}
	} else if n.StartAddress != "" && n.EndAddress != "" {
		data["cidr"] = n.StartAddress + " – " + n.EndAddress
	}

	// Registration and last-changed dates.
	for _, e := range n.Events {
		date := e.Date
		if len(date) > 10 {
			date = date[:10]
		}
		switch e.Action {
		case "registration":
			data["registered"] = date
		case "last changed":
			data["updated"] = date
		}
	}

	// RIR from self link.
	for _, l := range n.Links {
		if l.Rel == "self" {
			data["rir"] = rdapRIR(l.Href)
			break
		}
	}

	// Organization and ASN from entities.
	extractRDAPEntities(n.Entities, data)
}

func extractRDAPEntities(entities []rdapEntity, data map[string]any) {
	for _, ent := range entities {
		for _, role := range ent.Roles {
			if role == "registrant" {
				if org := vcardFN(ent.VcardArray); org != "" {
					data["organization"] = org
				}
				break
			}
		}
		// Recurse into nested entities (ARIN nests the registrant inside the network).
		extractRDAPEntities(ent.Entities, data)
	}
}

// vcardFN extracts the "fn" (full name) value from a vCard array.
// vCard format: ["vcard", [[name, params, type, value], ...]]
func vcardFN(vcardArray []any) string {
	if len(vcardArray) < 2 {
		return ""
	}
	props, ok := vcardArray[1].([]any)
	if !ok {
		return ""
	}
	for _, raw := range props {
		prop, ok := raw.([]any)
		if !ok || len(prop) < 4 {
			continue
		}
		if name, ok := prop[0].(string); ok && name == "fn" {
			if val, ok := prop[3].(string); ok {
				return val
			}
		}
	}
	return ""
}

func rdapRIR(href string) string {
	switch {
	case strings.Contains(href, "arin.net"):
		return "ARIN"
	case strings.Contains(href, "ripe.net"):
		return "RIPE"
	case strings.Contains(href, "apnic.net"):
		return "APNIC"
	case strings.Contains(href, "lacnic.net"):
		return "LACNIC"
	case strings.Contains(href, "afrinic.net"):
		return "AFRINIC"
	default:
		return ""
	}
}

// partialOrErr returns a partial ok result if PTR data is available, otherwise an error result.
func partialOrErr(name string, data map[string]any, msg string) (*model.SourceResult, error) {
	if len(data) > 0 {
		return &model.SourceResult{Name: name, Status: "ok", Data: data}, nil
	}
	return errResult(name, msg), nil
}

// ─── Domain enrichment via whoisparser ───────────────────────────────────────

func (w *WHOISEnricher) enrichDomain(ctx context.Context, domain string) (*model.SourceResult, error) {
	// whois.Whois performs a blocking port-43 lookup with no context support, so
	// run it in a goroutine and honor the caller's deadline via select. A timeout
	// is also pushed into the client so the goroutine cannot outlive the request.
	type whoisResult struct {
		raw string
		err error
	}
	ch := make(chan whoisResult, 1)
	go func() {
		client := whois.NewClient()
		if dl, ok := ctx.Deadline(); ok {
			if d := time.Until(dl); d > 0 {
				client.SetTimeout(d)
			}
		}
		raw, err := client.Whois(domain)
		ch <- whoisResult{raw: raw, err: err}
	}()

	var raw string
	select {
	case <-ctx.Done():
		return errResult(w.Name(), "WHOIS query cancelled: "+ctx.Err().Error()), nil
	case res := <-ch:
		if res.err != nil {
			return errResult(w.Name(), fmt.Sprintf("WHOIS query failed: %v", res.err)), nil
		}
		raw = res.raw
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		return &model.SourceResult{
			Name:   w.Name(),
			Status: "ok",
			Data:   map[string]any{"raw_note": "WHOIS response could not be parsed"},
		}, nil
	}

	data := map[string]any{}

	if parsed.Registrar != nil {
		setIfNotEmpty(data, "registrar", parsed.Registrar.Name)
	}
	if parsed.Registrant != nil {
		org := parsed.Registrant.Organization
		if org == "" {
			org = "Redacted"
		}
		data["registrant_organization"] = org
	}
	if parsed.Domain != nil {
		setIfNotEmpty(data, "created_date", parsed.Domain.CreatedDate)
		setIfNotEmpty(data, "updated_date", parsed.Domain.UpdatedDate)
		setIfNotEmpty(data, "expiration_date", parsed.Domain.ExpirationDate)
		if len(parsed.Domain.NameServers) > 0 {
			data["name_servers"] = parsed.Domain.NameServers
		}
		if len(parsed.Domain.Status) > 0 {
			data["status"] = parsed.Domain.Status
		}
	}

	return &model.SourceResult{
		Name:   w.Name(),
		Status: "ok",
		Data:   data,
		RawURL: fmt.Sprintf("https://lookup.icann.org/lookup?name=%s", domain),
	}, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func setIfNotEmpty(m map[string]any, key, val string) {
	if val != "" {
		m[key] = val
	}
}

func extractDomainFromURL(rawURL string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i != -1 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i != -1 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i != -1 {
		s = s[:i]
	}
	return s
}
