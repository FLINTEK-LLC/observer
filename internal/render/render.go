// Copyright (c) 2026 FLINTEK LLC
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the project root for license information.

package render

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/ctrlaltdean/observer/internal/model"
)

// Format selects the output renderer.
type Format string

const (
	FormatTable    Format = "table"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
	FormatCSV      Format = "csv"
)

// Render writes an EnrichmentResult in the chosen format to w.
func Render(result *model.EnrichmentResult, format Format, w io.Writer) error {
	switch format {
	case FormatJSON:
		return RenderJSON(result, w)
	case FormatMarkdown:
		return RenderMarkdown(result, w)
	case FormatCSV:
		return RenderCSV(result, w)
	default:
		return RenderTable(result, w)
	}
}

// ─── JSON ─────────────────────────────────────────────────────────────────────

func RenderJSON(result *model.EnrichmentResult, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// ─── CSV ──────────────────────────────────────────────────────────────────────

// RenderCSV outputs a flat table: observable,type,source,field,value.
func RenderCSV(result *model.EnrichmentResult, w io.Writer) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"observable", "type", "source", "field", "value"})

	// Deterministic source order.
	names := sortedKeys(result.Sources)
	for _, name := range names {
		sr := result.Sources[name]
		_ = cw.Write([]string{result.Observable, result.Type, name, "status", sr.Status})
		if sr.ErrorMessage != "" {
			_ = cw.Write([]string{result.Observable, result.Type, name, "error_message", sr.ErrorMessage})
		}
		flattenCSV(cw, result.Observable, result.Type, name, sr.Data, "")
	}
	cw.Flush()
	return cw.Error()
}

func flattenCSV(cw *csv.Writer, obs, oType, src string, m map[string]any, prefix string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := m[k]
		field := k
		if prefix != "" {
			field = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]any:
			flattenCSV(cw, obs, oType, src, val, field)
		case []any:
			parts := make([]string, 0, len(val))
			for _, item := range val {
				parts = append(parts, fmt.Sprintf("%v", item))
			}
			_ = cw.Write([]string{obs, oType, src, field, strings.Join(parts, "; ")})
		default:
			_ = cw.Write([]string{obs, oType, src, field, fmt.Sprintf("%v", val)})
		}
	}
}

// ─── Markdown ─────────────────────────────────────────────────────────────────

func RenderMarkdown(result *model.EnrichmentResult, w io.Writer) error {
	fmt.Fprintf(w, "# Observer Report\n\n")
	fmt.Fprintf(w, "**Observable:** `%s`  **Type:** %s  \n", result.Observable, result.Type)
	fmt.Fprintf(w, "**Timestamp:** %s UTC  \n\n", result.Timestamp.Format("2006-01-02 15:04:05"))

	// Classification section (IP only)
	if cl := classificationSection(result); cl != "" {
		fmt.Fprintf(w, "## Classification\n\n%s\n\n", cl)
	}

	// One section per source.
	names := sortedKeys(result.Sources)
	for _, name := range names {
		sr := result.Sources[name]
		fmt.Fprintf(w, "## %s\n\n", strings.ToUpper(name))
		fmt.Fprintf(w, "**Status:** %s  \n", sr.Status)
		if sr.ErrorMessage != "" {
			fmt.Fprintf(w, "**Error:** %s  \n", sr.ErrorMessage)
		}
		if sr.RawURL != "" {
			fmt.Fprintf(w, "**Source:** [%s](%s)  \n", name, sr.RawURL)
		}
		if len(sr.Data) > 0 {
			fmt.Fprintf(w, "\n| Field | Value |\n|---|---|\n")
			mdTable(w, sr.Data, "")
		}
		fmt.Fprintln(w)
	}
	return nil
}

func classificationSection(result *model.EnrichmentResult) string {
	var sb strings.Builder
	sb.WriteString("| Category | Value |\n|---|---|\n")

	ipinfo := result.Sources["ipinfo"]

	wrote := false

	if ipinfo != nil && ipinfo.Status == "ok" {
		rows := [][2]string{
			{"VPN", boolWithService(ipinfo.Data, "vpn", "service")},
			{"TOR", boolVal(ipinfo.Data, "tor")},
			{"Proxy", boolVal(ipinfo.Data, "proxy")},
			{"Hosting/DC", boolVal(ipinfo.Data, "hosting")},
		}
		for _, r := range rows {
			fmt.Fprintf(&sb, "| %s | %s |\n", r[0], r[1])
			wrote = true
		}
	}

	if !wrote {
		return ""
	}
	return sb.String()
}

func mdTable(w io.Writer, m map[string]any, prefix string) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := m[k]
		field := k
		if prefix != "" {
			field = prefix + "." + k
		}
		switch val := v.(type) {
		case map[string]any:
			mdTable(w, val, field)
		case []any:
			parts := make([]string, 0, len(val))
			for _, item := range val {
				parts = append(parts, fmt.Sprintf("%v", item))
			}
			fmt.Fprintf(w, "| %s | %s |\n", field, strings.Join(parts, ", "))
		default:
			fmt.Fprintf(w, "| %s | %v |\n", field, val)
		}
	}
}

// ─── Table (pretty, TTY-aware) ────────────────────────────────────────────────

func RenderTable(result *model.EnrichmentResult, w io.Writer) error {
	isTTY := isWriterTTY(w)

	var (
		styleBold    = lipgloss.NewStyle().Bold(true)
		styleHeader  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#A78BFA"))
		styleSection = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#60A5FA"))
		styleLabel   = lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8"))
		styleGreen   = lipgloss.NewStyle().Foreground(lipgloss.Color("#4ADE80"))
		styleRed     = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))
		styleYellow  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FBBF24"))
		styleGrey    = lipgloss.NewStyle().Foreground(lipgloss.Color("#6B7280"))
		styleDim     = lipgloss.NewStyle().Foreground(lipgloss.Color("#CBD5E1"))
	)

	applyIf := func(s lipgloss.Style, text string) string {
		if isTTY {
			return s.Render(text)
		}
		return text
	}

	sep := strings.Repeat("─", 60)

	// ── Header ──────────────────────────────────────────────────────────────
	fmt.Fprintln(w, sep)
	header := fmt.Sprintf("  OBSERVER  │  %s  (%s)  │  %s",
		result.Observable, result.Type,
		result.Timestamp.Format("2006-01-02 15:04"))
	fmt.Fprintln(w, applyIf(styleHeader, header))
	fmt.Fprintln(w, sep)
	fmt.Fprintln(w)

	// ── Classification ────────────────────────────────────────────────────
	ipinfo := result.Sources["ipinfo"]

	hasClassification := ipinfo != nil && ipinfo.Status == "ok"

	if hasClassification {
		fmt.Fprintln(w, applyIf(styleSection, "CLASSIFICATION"))

		d := ipinfo.Data

		printBoolRow(w, applyIf, styleLabel, styleGreen, styleRed, styleDim,
			"VPN", getBool(d, "vpn"), getString(d, "service"))
		printBoolRow(w, applyIf, styleLabel, styleRed, styleGrey, styleDim,
			"TOR", getBool(d, "tor"), "")
		printBoolRow(w, applyIf, styleLabel, styleYellow, styleGrey, styleDim,
			"Proxy", getBool(d, "proxy"), "")
		printBoolRow(w, applyIf, styleLabel, styleYellow, styleGrey, styleDim,
			"Hosting/DC", getBool(d, "hosting"), getString(d, "org"))

		if pa, _ := d["privacy_available"].(bool); !pa {
			fmt.Fprintf(w, "  %-14s %s\n",
				applyIf(styleLabel, "Privacy"),
				applyIf(styleGrey, "(token required for VPN/TOR/proxy data)"))
		}
		fmt.Fprintln(w)
	}

	// ── Geo & Network ─────────────────────────────────────────────────────
	shodan := result.Sources["shodan"]
	if ipinfo != nil || shodan != nil {
		fmt.Fprintln(w, applyIf(styleSection, "GEO & NETWORK"))

		// Location
		if ipinfo != nil && ipinfo.Status == "ok" {
			d := ipinfo.Data
			city, region, country := getString(d, "city"), getString(d, "region"), getString(d, "country")
			loc := joinNonEmpty(", ", city, region, country)
			if loc != "" {
				fmt.Fprintf(w, "  %-14s %s\n", applyIf(styleLabel, "Location"), applyIf(styleBold, loc))
			}
			if org := getString(d, "org"); org != "" {
				fmt.Fprintf(w, "  %-14s %s\n", applyIf(styleLabel, "ASN/Org"), applyIf(styleDim, org))
			}
		}

		if shodan != nil && shodan.Status == "ok" {
			d := shodan.Data
			if ports := anyToStringSlice(d["ports"]); len(ports) > 0 {
				fmt.Fprintf(w, "  %-14s %s\n", applyIf(styleLabel, "Ports"), applyIf(styleDim, strings.Join(ports, ", ")))
			}
			if hostnames := anyToStringSlice(d["hostnames"]); len(hostnames) > 0 {
				fmt.Fprintf(w, "  %-14s %s\n", applyIf(styleLabel, "Hostnames"), applyIf(styleDim, strings.Join(hostnames, ", ")))
			}
			if tags := anyToStringSlice(d["tags"]); len(tags) > 0 {
				fmt.Fprintf(w, "  %-14s %s\n", applyIf(styleLabel, "Tags"), applyIf(styleYellow, strings.Join(tags, ", ")))
			}
		}

		// PTR records from WHOIS rDNS lookup.
		if whoisSrc := result.Sources["whois"]; whoisSrc != nil && whoisSrc.Status == "ok" {
			if ptrs := anyToStringSlice(whoisSrc.Data["ptr_records"]); len(ptrs) > 0 {
				fmt.Fprintf(w, "  %-14s %s\n", applyIf(styleLabel, "PTR"), applyIf(styleDim, strings.Join(ptrs, ", ")))
			}
		}

		fmt.Fprintln(w)
	}

	// ── Reputation ────────────────────────────────────────────────────────
	vt := result.Sources["virustotal"]
	abuse := result.Sources["abuseipdb"]
	otx := result.Sources["otx"]

	if vt != nil || abuse != nil || otx != nil {
		fmt.Fprintln(w, applyIf(styleSection, "REPUTATION"))

		if vt != nil && vt.Status == "ok" && len(vt.Data) > 0 {
			malicious := getInt(vt.Data, "malicious")
			total := malicious + getInt(vt.Data, "suspicious") + getInt(vt.Data, "harmless") + getInt(vt.Data, "undetected")
			vtStr := fmt.Sprintf("%d / %d engines", malicious, total)
			if ts := getInt64(vt.Data, "last_analysis_date"); ts > 0 {
				vtStr += fmt.Sprintf("  [last: %s]", time.Unix(ts, 0).Format("2006-01-02"))
			}
			vtStyle := styleGrey
			if malicious > 0 {
				vtStyle = styleRed
			}
			fmt.Fprintf(w, "  %-14s %s\n", applyIf(styleLabel, "VirusTotal"), applyIf(vtStyle, vtStr))
		} else if vt != nil && vt.Status != "ok" && vt.Status != "unsupported" {
			fmt.Fprintf(w, "  %-14s %s\n", applyIf(styleLabel, "VirusTotal"), applyIf(styleGrey, "("+vt.Status+")"))
		}

		if abuse != nil && abuse.Status == "ok" {
			d := abuse.Data
			score := getInt(d, "abuse_confidence_score")
			reports := getInt(d, "total_reports")
			last := getString(d, "last_reported_at")
			if len(last) > 10 {
				last = last[:10]
			}
			abuseStr := fmt.Sprintf("%d%% confidence  │  %d reports", score, reports)
			if last != "" {
				abuseStr += "  │  last: " + last
			}
			abuseStyle := styleGrey
			if score >= 75 {
				abuseStyle = styleRed
			} else if score >= 25 {
				abuseStyle = styleYellow
			} else if score > 0 {
				abuseStyle = styleGreen
			}
			fmt.Fprintf(w, "  %-14s %s\n", applyIf(styleLabel, "AbuseIPDB"), applyIf(abuseStyle, abuseStr))
		}

		if otx != nil && otx.Status == "ok" {
			d := otx.Data
			count := getInt(d, "pulse_count")
			otxStr := fmt.Sprintf("%d pulses", count)
			if pulses, ok := d["pulses"].([]map[string]any); ok && len(pulses) > 0 {
				names := make([]string, 0, len(pulses))
				for _, p := range pulses {
					if n, ok := p["name"].(string); ok && n != "" {
						names = append(names, n)
					}
				}
				if len(names) > 0 {
					otxStr += "  →  " + strings.Join(names, ", ")
				}
			}
			otxStyle := styleGrey
			if count > 0 {
				otxStyle = styleRed
			}
			fmt.Fprintf(w, "  %-14s %s\n", applyIf(styleLabel, "OTX"), applyIf(otxStyle, otxStr))
		}
		fmt.Fprintln(w)
	}

	// ── WHOIS ─────────────────────────────────────────────────────────────
	whoisSrc := result.Sources["whois"]
	if whoisSrc != nil && whoisSrc.Status == "ok" {
		d := whoisSrc.Data
		isIP := result.Type == "IPv4" || result.Type == "IPv6"

		// For IPs: only render the section when we have actual RDAP data.
		// PTR records are shown in Geo & Network; don't show an empty WHOIS block.
		ipFields := []string{"organization", "network_name", "cidr", "country", "asn", "registered", "updated", "rir"}
		hasIPData := false
		if isIP {
			for _, k := range ipFields {
				if getString(d, k) != "" {
					hasIPData = true
					break
				}
			}
		}

		if !isIP || hasIPData {
			fmt.Fprintln(w, applyIf(styleSection, "WHOIS ("+result.Type+")"))

			if isIP {
				for _, row := range [][2]string{
					{"Organization", getString(d, "organization")},
					{"Network", getString(d, "network_name")},
					{"CIDR", getString(d, "cidr")},
					{"Country", getString(d, "country")},
					{"ASN", getString(d, "asn")},
					{"Registered", getString(d, "registered")},
					{"Updated", getString(d, "updated")},
					{"RIR", getString(d, "rir")},
				} {
					if row[1] != "" {
						fmt.Fprintf(w, "  %-24s %s\n", applyIf(styleLabel, row[0]), applyIf(styleDim, row[1]))
					}
				}
			} else {
				for _, k := range []string{"registrar", "registrant_organization", "created_date", "updated_date", "expiration_date", "status"} {
					if v := getString(d, k); v != "" {
						display := titleWords(strings.ReplaceAll(k, "_", " "))
						fmt.Fprintf(w, "  %-24s %s\n", applyIf(styleLabel, display), applyIf(styleDim, v))
					}
				}
				if ns := anyToStringSlice(d["name_servers"]); len(ns) > 0 {
					fmt.Fprintf(w, "  %-24s %s\n", applyIf(styleLabel, "Name Servers"), applyIf(styleDim, strings.Join(ns, ", ")))
				}
			}
			fmt.Fprintln(w)
		}
	}

	// ── Sources status ────────────────────────────────────────────────────
	fmt.Fprintln(w, applyIf(styleSection, "SOURCES"))
	names := sortedKeys(result.Sources)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		sr := result.Sources[name]
		var icon, text string
		switch sr.Status {
		case "ok":
			icon = "✅"
			text = termLink(isTTY, name, sr.RawURL)
			text = applyIf(styleGreen, text)
		case "rate_limited":
			icon = "⚠️"
			text = termLink(isTTY, name+" [rate limited]", sr.RawURL)
			text = applyIf(styleYellow, text)
		case "error":
			icon = "❌"
			text = termLink(isTTY, name+" [error]", sr.RawURL)
			text = applyIf(styleRed, text)
		case "unsupported":
			icon = "—"
			text = applyIf(styleGrey, name)
		default:
			icon = "?"
			text = name
		}
		parts = append(parts, icon+" "+text)
	}
	fmt.Fprintln(w, " ", strings.Join(parts, "  "))
	fmt.Fprintln(w, sep)
	return nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

func isWriterTTY(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		return term.IsTerminal(int(f.Fd()))
	}
	return false
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func getInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return 0
}

func getInt64(m map[string]any, key string) int64 {
	if m == nil {
		return 0
	}
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case int64:
			return n
		case int:
			return int64(n)
		case float64:
			return int64(n)
		}
	}
	return 0
}

func anyToStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case []string:
		return val
	case []any:
		result := make([]string, 0, len(val))
		for _, item := range val {
			result = append(result, fmt.Sprintf("%v", item))
		}
		return result
	case []int:
		result := make([]string, len(val))
		for i, n := range val {
			result[i] = fmt.Sprintf("%d", n)
		}
		return result
	case []float64:
		result := make([]string, len(val))
		for i, n := range val {
			result[i] = fmt.Sprintf("%g", n)
		}
		return result
	}
	return nil
}

func formatBool(b bool) string {
	if b {
		return "YES"
	}
	return "No"
}

func boolVal(m map[string]any, key string) string {
	return formatBool(getBool(m, key))
}

func boolWithService(m map[string]any, boolKey, svcKey string) string {
	b := getBool(m, boolKey)
	s := formatBool(b)
	if b {
		if svc := getString(m, svcKey); svc != "" {
			s += " (" + svc + ")"
		}
	}
	return s
}

func printBoolRow(
	w io.Writer,
	applyIf func(lipgloss.Style, string) string,
	labelStyle, trueStyle, falseStyle, dimStyle lipgloss.Style,
	label string, val bool, extra string,
) {
	s := formatBool(val)
	style := falseStyle
	if val {
		style = trueStyle
		if extra != "" {
			s += " (" + extra + ")"
		}
	}
	fmt.Fprintf(w, "  %-14s %s\n", applyIf(labelStyle, label), applyIf(style, s))
}

// titleWords upper-cases the first letter of each space-separated word. It
// replaces the deprecated strings.Title for the ASCII field labels used here.
func titleWords(s string) string {
	words := strings.Fields(s)
	for i, word := range words {
		words[i] = strings.ToUpper(word[:1]) + word[1:]
	}
	return strings.Join(words, " ")
}

func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// termLink wraps text in an OSC 8 terminal hyperlink when writing to a TTY.
// Supported by Windows Terminal, iTerm2, GNOME Terminal, and most modern terminals.
// Falls back to plain text when url is empty or not a TTY.
func termLink(isTTY bool, text, url string) string {
	if !isTTY || url == "" {
		return text
	}
	return "\x1b]8;;" + url + "\x1b\\" + text + "\x1b]8;;\x1b\\"
}
