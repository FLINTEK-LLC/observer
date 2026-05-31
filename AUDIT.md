# FLINTEK LLC — Observer Audit Report

**Date:** 2026-05-30
**Module:** `github.com/flintek-llc/observer`
**Scope:** GreyNoise removal, Apache-2.0 license adoption, security audit, efficiency audit.
**Build status after changes:** `go build ./...`, `go vet ./...`, and `go test ./...` all pass.

---

## GreyNoise Removal Summary

GreyNoise was a paid source and has been removed in full. The source count dropped
from **7 → 6** (shodan, virustotal, abuseipdb, whois, otx, ipinfo).

### Files deleted
| File | Reason |
|---|---|
| `internal/enricher/greynoise.go` | Entire `GreyNoiseEnricher` client (struct, `NewGreyNoise`, `Name`, `SupportedTypes`, `Enrich`). |
| `internal/enricher/greynoise_test.go` | All GreyNoise unit tests. |

### Files edited
| File | Change |
|---|---|
| `config/config.go` | Removed `GreyNoiseAPIKey` struct field, the `os.Getenv("GREYNOISE_API_KEY")` load, and the `"greynoise"` entry in `ActiveSources()`. |
| `internal/runner/runner.go` | Removed the `cfg.GreyNoiseAPIKey != ""` block in `buildEnrichers()` that appended `enricher.NewGreyNoise(...)`. |
| `cmd/server/main.go` | Removed `greynoise=%v` from the startup source-status log line and its argument. |
| `cmd/observe/main.go` | Removed `"greynoise"` from the `config` command's source name list. |
| `web/handler.go` | Removed the `greynoise` entry from the `/api/sources` response. |
| `internal/render/render.go` | Removed the GreyNoise "GN Noise"/"GN RIOT" blocks from both the Markdown `classificationSection()` and the table `RenderTable()` classification section. |
| `web/static/index.html` | Removed the GreyNoise classification badges and the `'greynoise'` entry from `sourceOrder`. |
| `internal/keysmgr/keysmgr.go` | Removed the `GREYNOISE_API_KEY` entry from `AllKeys`. |
| `README.md` | "seven … sources" → "six"; removed GreyNoise rows from the config table, source-coverage matrix, and signup-link table. |
| `.env.example` | Removed the `GREYNOISE_API_KEY` block. |

### Fan-out / concurrency review
The fan-out in `internal/runner/runner.go` is **fully dynamic** — it iterates
`enrichers` and uses `sync.WaitGroup` + a mutex-guarded map sized with
`len(enrichers)`. There was **no hardcoded source count** in the concurrency
logic, so no concurrency constant needed updating. The only hardcoded source
*lists* were the display/order lists noted above, all updated.

### Verification
`grep -ri greynoise` across the tree (excluding `.git`) returns **no matches**.
No dead code, commented blocks, or TODO stubs were left behind.

---

## License Updates

Target: **Apache License, Version 2.0**, © 2026 FLINTEK LLC.

1. **`LICENSE` (new, repo root)** — full Apache-2.0 text, prefixed with the
   required `Copyright (c) 2026 FLINTEK LLC` boilerplate notice.
2. **Per-file headers** — the 3-line header was prepended (before the `package`
   clause, above any package doc comment) to **all 26 `.go` files**:
   ```go
   // Copyright (c) 2026 FLINTEK LLC
   // Licensed under the Apache License, Version 2.0.
   // See LICENSE in the project root for license information.
   ```
   Files: `cmd/observe/main.go`, `cmd/server/main.go`, `config/config.go`,
   `internal/detect/{detect,detect_test}.go`,
   `internal/enricher/{abuseipdb,abuseipdb_test,enricher,enricher_test,ipinfo,ipinfo_test,otx,otx_test,shodan,shodan_test,virustotal,virustotal_test,whois,whois_test}.go`,
   `internal/keysmgr/keysmgr.go`, `internal/model/model.go`,
   `internal/render/render.go`, `internal/runner/{runner,runner_test}.go`,
   `web/handler.go`, `web/middleware.go`.
3. **`README.md`** — added a `## License` section at the bottom with the
   `SPDX-License-Identifier: Apache-2.0` identifier, FLINTEK LLC ownership, and a
   link to `LICENSE`.
4. **`go.mod`** — carries no license metadata by design; the module path was left
   unchanged. No inline license references existed elsewhere.

There was **no pre-existing LICENSE file or copyright header** in the repo prior
to this change (the project was effectively unlicensed / all-rights-reserved).

---

## Security Findings (HIGH / MEDIUM / LOW)

### HIGH

#### H-1 — Shodan API key leaked into error messages, logs, and API responses  ✅ FIXED
**File:** `internal/enricher/shodan.go:52` (and error paths at `:57`, `:62`)

Shodan passes the key as a URL query parameter:
```go
url := fmt.Sprintf("%s/shodan/host/%s?key=%s", s.baseURL, ip, s.apiKey)
...
resp, err := s.client.Do(req)
if err != nil {
    return errResult(s.Name(), fmt.Sprintf("connection failed: %v", err)), nil
}
```
**Risk:** Go's `net/http` client embeds the full request URL in its error
strings (e.g. `Get "https://api.shodan.io/shodan/host/1.2.3.4?key=SECRET": ...`).
That string is stored in `SourceResult.ErrorMessage`, which is (a) returned in
`/api/enrich` JSON responses to API clients and (b) renderable to output/logs.
In server mode this discloses the operator's Shodan key across a trust boundary.

**Fix applied:** Added `sanitizeErr(err, secret)` in `internal/enricher/enricher.go`
which redacts the key from any error string, and wired it into both Shodan error
paths:
```go
return errResult(s.Name(), fmt.Sprintf("connection failed: %s", sanitizeErr(err, s.apiKey))), nil
```
Shodan is the only source that puts the key in the URL; all others use headers,
so no other enricher is affected.

### MEDIUM

#### M-1 — HTTP server has no timeouts (Slowloris / connection-exhaustion DoS)  ✅ FIXED
**File:** `cmd/server/main.go`
**Fix applied:** replaced `http.ListenAndServe` with a configured `*http.Server`
(`ReadHeaderTimeout 10s`, `ReadTimeout 30s`, `WriteTimeout 120s` — exceeds the
bulk handler's 60s budget — `IdleTimeout 120s`).
```go
if err := http.ListenAndServe(addr, mux); err != nil {
```
`http.ListenAndServe` uses a zero-value server: no `ReadTimeout`,
`ReadHeaderTimeout`, `WriteTimeout`, or `IdleTimeout`. A slow client can hold
connections open indefinitely.
**Recommended fix:**
```go
srv := &http.Server{
    Addr:              addr,
    Handler:           mux,
    ReadHeaderTimeout: 10 * time.Second,
    ReadTimeout:       30 * time.Second,
    WriteTimeout:      90 * time.Second, // ≥ bulk ctx (60s) + margin
    IdleTimeout:       120 * time.Second,
}
if err := srv.ListenAndServe(); err != nil { ... }
```

#### M-2 — Non-constant-time API key comparison (timing side-channel)  ✅ FIXED
**File:** `web/middleware.go`
**Fix applied:** now uses `crypto/subtle.ConstantTimeCompare`.
```go
if provided != apiKey {
```
String `!=` short-circuits on the first differing byte, leaking key length and a
prefix-match oracle via response timing.
**Recommended fix:** `crypto/subtle.ConstantTimeCompare([]byte(provided), []byte(apiKey)) != 1`.

#### M-3 — Bulk endpoint accepts unbounded observable count (memory-exhaustion DoS)  ✅ FIXED
**File:** `web/handler.go`
**Fix applied:** `http.MaxBytesReader` caps the body at 1 MiB and requests with
more than `maxBulkObservables` (1000) entries are rejected with `413`.
```go
Observables []string `json:"observables"`
...
results := make([]any, len(body.Observables))
resultCh := make(chan indexedResult, len(body.Observables))
```
There is no cap on `len(body.Observables)` and no `http.MaxBytesReader` on the
request body. A client can POST a huge array, forcing a large channel + slice
allocation (and one queued goroutine per item). Concurrency is bounded by `sem`,
but memory and request size are not.
**Recommended fix:** Enforce a max (e.g. 1000) and reject larger payloads with
`400`; wrap `r.Body` with `http.MaxBytesReader`. The CLI `bulk` path
(`cmd/observe/main.go`) is local-trust and lower priority.

#### M-4 — Context not propagated to domain WHOIS lookup  ✅ FIXED
**File:** `internal/enricher/whois.go`
**Fix applied:** `enrichDomain` now takes `ctx`, runs the blocking `whois`
lookup in a goroutine, pushes the context deadline into the client via
`SetTimeout`, and returns promptly on `ctx.Done()`.

*Original analysis:*
```go
func (w *WHOISEnricher) enrichDomain(domain string) (*model.SourceResult, error) {
    raw, err := whois.Whois(domain)
```
`enrichDomain` neither accepts nor honors the per-enricher `context.Context`. The
runner's `context.WithTimeout` cancels the goroutine, but the blocking
`whois.Whois` TCP call (port 43) keeps running, so the deadline is not enforced
for domain/URL inputs. (Also listed under Efficiency E-4.)
**Recommended fix:** Thread `ctx` into `enrichDomain`; use the `likexian/whois`
client's timeout setter, or run the lookup in a goroutine and select on
`ctx.Done()`.

### LOW

#### L-1 — Meaningful error returns discarded with `_`  ✅ FIXED (CLI bulk)
- `cmd/observe/main.go` — the discarded `enc.Encode(results)` and
  `render.Render(...)` in bulk mode now log to stderr on failure.
- `web/middleware.go` / `web/handler.go` — `_ = json.NewEncoder(w).Encode(...)`
  in `writeJSON`/`writeError` left as-is (idiomatic for `http.ResponseWriter`;
  the response is already committed at that point).
- `RenderCSV` ignores per-row `cw.Write` errors but checks `cw.Error()` at the
  end, which is correct (unchanged).

#### L-2 — `exec` relies on `PATH` resolution  ✅ FIXED
**File:** `cmd/observe/main.go` (`runUpdate`)
Now resolves `go` with `exec.LookPath("go")` and reports a clear error (pointing
to the manual download) when it is absent.

#### L-3 — Bulk file path taken from CLI argument
**File:** `cmd/observe/main.go` (`os.Open(args[0])`)
Path traversal is not meaningful here (local CLI, user's own privileges), noted
for completeness.

### Items reviewed and found clean
- **No hardcoded credentials/secrets** in source (test files use literal
  `"test-key"` only).
- **No `InsecureSkipVerify`** or weakened TLS anywhere; all clients use defaults.
- **No `unsafe`** package usage.
- **Input validation:** all observables pass `detect.Detect` (IP via
  `net.ParseIP`, hashes via exact-length hex regex, domains via RFC-ish regex)
  before use; unknown types are rejected. Go's `regexp` (RE2) is linear-time, so
  the domain regex is **not** ReDoS-vulnerable (the equivalent client-side JS
  regex in `index.html` runs only in the browser).
- **No SQL** / template injection surface; URL components are validated or
  `url.PathEscape`/`url.Values`-encoded (abuseipdb, otx URL path).
- **Race conditions:** all writes to `result.Sources` in `runner.go` occur under
  `mu`; the web bulk aggregator writes the results slice from a single reader
  goroutine. Clean.
- **Goroutine leaks:** runner goroutines are bounded by `WaitGroup`+timeout; web
  bulk uses a buffered `resultCh` sized to the work count plus a closer goroutine
  — no blocking sends. Clean.
- **Outbound HTTP timeouts:** `newHTTPClient` sets a 10s client timeout. Good.

---

## Efficiency Findings

### Applied
#### E-1 — Pre-allocate the enricher slice  ✅ APPLIED
**File:** `internal/runner/runner.go` (`buildEnrichers`)
Changed `var list []enricher.Enricher` → `list := make([]enricher.Enricher, 0, 6)`
(max source count is known), avoiding incremental slice growth on each `append`.

### Applied (flagged items, now fixed)

#### E-2 — Duplicated HTTP request/response boilerplate across enrichers  ✅ FIXED
**Files:** `internal/enricher/{enricher,shodan,virustotal,abuseipdb,otx,ipinfo}.go`
Added `classifyStatus(name, code) *model.SourceResult` to `enricher.go`
(`429 → rate_limited`, `5xx → server error`, `4xx → client error`, else `nil`)
and replaced the repeated status switch in all five HTTP enrichers. Each source
keeps its own `404`/`200` special-casing before delegating to the helper
(Shodan also keeps its `unexpected status` fallback for non-200/2xx). This also
centralizes the credential-redaction concern from H-1.

#### E-3 — One `*http.Client` allocated per enricher  ✅ FIXED
**File:** `internal/enricher/enricher.go`
`newHTTPClient` now returns a single package-level `sharedHTTPClient`, pooling
connections across all sources. `*http.Client` is safe for concurrent use.

#### E-4 — Missing context propagation in `enrichDomain`  ✅ FIXED (see M-4)
A hung WHOIS lookup no longer outlives the caller's deadline.

#### E-6 — `strings.Title` is deprecated  ✅ FIXED
**File:** `internal/render/render.go`
Replaced with a local `titleWords` helper (ASCII title-casing of field labels),
preserving the existing rendered output without the deprecated API.

#### E-7 — Redundant local `min` helper  ✅ FIXED
**File:** `internal/keysmgr/keysmgr.go`
Deleted; `maskKey` now uses the Go 1.21+ builtin `min` (module targets `go 1.22`).

#### E-8 — Minor slice pre-allocation  ✅ FIXED
**File:** `cmd/observe/main.go`
Both `srcList` builders now `make([]string, 0, len(parts))`.

#### Error wrapping  ✅ FIXED (runner)
- `internal/runner/runner.go` now wraps the detect error:
  `fmt.Errorf("detect observable: %w", err)`.
- Enricher failures are stored as `SourceResult.ErrorMessage` *strings* (not
  returned as `error` values), so `%w` does not apply there; `%v` is correct in
  that context. CLI top-level wrapping already uses `%w`.

### Flagged — intentionally not changed

#### E-5 — `result.Sources` aggregation via `errgroup`
**File:** `internal/runner/runner.go` (`RunWithOptions`)
`errgroup`'s value is abort-on-first-error cancellation, but the runner
**intentionally collects every source's result** (including errors) and never
aborts siblings. Converting would either change that semantic or add a
dependency for no behavioral gain, so the correct `WaitGroup` + `sync.Mutex`
pattern was left in place.

---

## Dependency License Flags

Reviewed all `require` entries in `go.mod`. **No GPL-2.0, LGPL-2.x, or
proprietary dependencies were found.** All are permissive and compatible with
Apache-2.0 distribution.

| Module | License | Compatible? |
|---|---|---|
| github.com/charmbracelet/bubbles | MIT | ✅ |
| github.com/charmbracelet/bubbletea | MIT | ✅ |
| github.com/charmbracelet/lipgloss | MIT | ✅ |
| github.com/joho/godotenv | MIT | ✅ |
| github.com/likexian/whois | Apache-2.0 | ✅ |
| github.com/likexian/whois-parser | Apache-2.0 | ✅ |
| github.com/spf13/cobra | Apache-2.0 | ✅ |
| golang.org/x/term, x/net, x/sync, x/sys, x/text | BSD-3-Clause | ✅ |
| github.com/likexian/gokit *(indirect)* | Apache-2.0 | ✅ |
| github.com/spf13/pflag *(indirect)* | BSD-3-Clause | ✅ |
| github.com/atotto/clipboard *(indirect)* | BSD-3-Clause | ✅ |
| github.com/aymanbagabas/go-osc52/v2 *(indirect)* | MIT | ✅ |
| github.com/containerd/console *(indirect)* | Apache-2.0 | ✅ |
| github.com/inconshreveable/mousetrap *(indirect)* | Apache-2.0 | ✅ |
| github.com/lucasb-eyer/go-colorful *(indirect)* | MIT | ✅ |
| github.com/mattn/go-isatty *(indirect)* | MIT | ✅ |
| github.com/mattn/go-localereader *(indirect)* | MIT | ✅ |
| github.com/mattn/go-runewidth *(indirect)* | MIT | ✅ |
| github.com/muesli/ansi, cancelreader, reflow, termenv *(indirect)* | MIT | ✅ |
| github.com/rivo/uniseg *(indirect)* | MIT | ✅ |

> Licenses listed reflect each project's published upstream license. Verify with
> a tool such as `go-licenses` before each release to catch upstream changes.

---

## Summary of Changes Applied

**GreyNoise removal (Part 1)**
- Deleted `internal/enricher/greynoise.go` and `greynoise_test.go`.
- Cleaned references in `config/config.go`, `internal/runner/runner.go`,
  `cmd/server/main.go`, `cmd/observe/main.go`, `web/handler.go`,
  `internal/render/render.go`, `web/static/index.html`,
  `internal/keysmgr/keysmgr.go`, `README.md`, `.env.example`.

**License (Part 2)**
- Created `LICENSE` (Apache-2.0 + FLINTEK LLC notice).
- Added the copyright header to all 26 `.go` files.
- Added a `## License` section (with SPDX id) to `README.md`.

**Security (Part 3) — all findings now fixed**
- **H-1:** added `sanitizeErr` in `internal/enricher/enricher.go` and applied it
  to both Shodan error paths to prevent API-key leakage.
- **M-1:** configured `*http.Server` timeouts in `cmd/server/main.go`.
- **M-2:** constant-time API-key comparison in `web/middleware.go`.
- **M-3:** body size + observable-count caps on the bulk endpoint in `web/handler.go`.
- **M-4:** context/deadline now honored by the WHOIS domain lookup.
- **L-1:** CLI bulk mode logs previously-discarded encode/render errors.
- **L-2:** `runUpdate` resolves `go` via `exec.LookPath`.

**Efficiency (Part 4)**
- **E-1:** pre-allocated the enricher slice in `buildEnrichers`.
- **E-2:** shared `classifyStatus` helper across the HTTP enrichers.
- **E-3:** single shared `*http.Client`.
- **E-4:** context propagated into WHOIS (see M-4).
- **E-6:** replaced deprecated `strings.Title` with `titleWords`.
- **E-7:** removed redundant `min` helper (builtin).
- **E-8:** pre-allocated `srcList` slices.
- Error wrapping: runner wraps the detect error with `%w`.
- **E-5 intentionally not changed** (errgroup semantics don't fit; see above).

**Incidental fix**
- Repaired a pre-existing **syntax error** in the (untracked)
  `internal/enricher/enricher_test.go` — a stray extra `}` plus space-indentation
  that would have broken `go test`/`go vet` for the whole module. With it fixed,
  the full test suite compiles and passes.

**Verification:** `go build ./...`, `go vet ./...`, and `go test ./...` all pass;
`gofmt` clean.

---

## Recommended Follow-up Items

All HIGH/MEDIUM/LOW security findings and all flagged efficiency items (except
E-5, intentionally declined) have been fixed in this change. Remaining
recommendations are process/hygiene only:

1. **Tests for the new hardening:** add unit tests for the bulk caps (M-3,
   413 on >1000 / oversized body), the constant-time auth path (M-2), and WHOIS
   context cancellation (M-4).
2. **Release hygiene:** add a `go-licenses` (or equivalent) check to CI to flag
   any future incompatible transitive dependency, and consider adding a `NOTICE`
   file per Apache-2.0 §4(d) attribution conventions.
3. **Process:** the unlicensed history means prior commits had no license grant;
   confirm all contributors are covered by the new Apache-2.0 + FLINTEK LLC
   ownership before publishing.
4. **E-5 (optional):** revisit an `errgroup`-based runner only if abort-on-error
   semantics ever become desirable.
