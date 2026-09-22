// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package enricher

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/flintek-llc/observer/internal/detect"
	"github.com/flintek-llc/observer/internal/model"
)

// X4BNetEnricher checks IPs against the X4BNet VPN netblock list
// (github.com/X4BNet/lists_vpn, MIT). The list is ASN-derived, so a match
// means the IP sits in a range owned by a known VPN provider — a
// corroborating signal, not per-IP attribution.
//
// Lists are fetched on demand; nothing is written to disk. The runner builds
// fresh enrichers per request, so parsed lists are held in a package-level
// cache for x4bTTL to avoid refetching (and GitHub 429s) during bulk lookups
// in server mode.
type X4BNetEnricher struct {
	baseURL string
	client  *http.Client
}

const x4bTTL = 15 * time.Minute

type x4bList struct {
	prefixes  []netip.Prefix
	fetchedAt time.Time
}

var x4bCache = struct {
	sync.Mutex
	lists map[string]*x4bList
}{lists: map[string]*x4bList{}}

func NewX4BNet() *X4BNetEnricher {
	return &X4BNetEnricher{
		baseURL: "https://raw.githubusercontent.com/X4BNet/lists_vpn/main",
		client:  newHTTPClient(),
	}
}

func (x *X4BNetEnricher) Name() string { return "x4bnet" }

func (x *X4BNetEnricher) SupportedTypes() []detect.ObservableType {
	return []detect.ObservableType{detect.TypeIPv4, detect.TypeIPv6}
}

func (x *X4BNetEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
	if !supportsType(x.SupportedTypes(), oType) {
		return unsupportedResult(x.Name()), ErrUnsupportedType
	}

	addr, err := netip.ParseAddr(observable)
	if err != nil {
		return errResult(x.Name(), fmt.Sprintf("invalid IP: %v", err)), nil
	}
	addr = addr.Unmap()

	file := "output/vpn/ipv4.txt"
	if addr.Is6() {
		file = "output/vpn/ipv6.txt"
	}
	listURL := x.baseURL + "/" + file

	list, sr := x.load(ctx, listURL)
	if sr != nil {
		return sr, nil
	}

	data := map[string]any{
		"vpn":        false,
		"list_size":  len(list.prefixes),
		"fetched_at": list.fetchedAt.UTC().Format(time.RFC3339),
	}
	for _, p := range list.prefixes {
		if p.Contains(addr) {
			data["vpn"] = true
			data["matched_cidr"] = p.String()
			break
		}
	}

	return &model.SourceResult{
		Name:   x.Name(),
		Status: "ok",
		Data:   data,
		RawURL: "https://github.com/X4BNet/lists_vpn/blob/main/" + file,
	}, nil
}

// load returns the cached list for listURL, fetching it if absent or stale.
// The lock is held across the fetch so concurrent lookups share one download.
func (x *X4BNetEnricher) load(ctx context.Context, listURL string) (*x4bList, *model.SourceResult) {
	x4bCache.Lock()
	defer x4bCache.Unlock()

	if l := x4bCache.lists[listURL]; l != nil && time.Since(l.fetchedAt) < x4bTTL {
		return l, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return nil, errResult(x.Name(), fmt.Sprintf("request error: %v", err))
	}
	resp, err := x.client.Do(req)
	if err != nil {
		return nil, errResult(x.Name(), fmt.Sprintf("connection failed: %v", err))
	}
	defer resp.Body.Close()

	if sr := classifyStatus(x.Name(), resp.StatusCode); sr != nil {
		return nil, sr
	}

	prefixes, err := parseCIDRList(resp.Body)
	if err != nil {
		return nil, errResult(x.Name(), fmt.Sprintf("read error: %v", err))
	}
	if len(prefixes) == 0 {
		return nil, errResult(x.Name(), "list was empty")
	}

	l := &x4bList{prefixes: prefixes, fetchedAt: time.Now()}
	x4bCache.lists[listURL] = l
	return l, nil
}

// parseCIDRList reads one CIDR (or bare IP) per line, skipping blanks,
// comments, and malformed entries.
func parseCIDRList(r io.Reader) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if p, err := netip.ParsePrefix(line); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(line); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, sc.Err()
}
