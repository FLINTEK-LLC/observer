# Observer

**Observable enrichment tool for defenders, analysts, and incident responders.**

Observer accepts a network observable — an IP address, domain, URL, or file hash — fans it out to six threat intelligence sources simultaneously, and returns normalized, structured results. It ships as both a CLI binary and a self-hosted web server with a browser UI.

---

## Contents

1. [Installation](#installation)
2. [Quick start](#quick-start)
3. [Configuration](#configuration)
4. [CLI reference](#cli-reference)
5. [Server setup](#server-setup)
6. [API reference](#api-reference)
7. [Source coverage](#source-coverage)
8. [Adding an enricher](#adding-an-enricher)
9. [API key signup links](#api-key-signup-links)

---

## Installation

### go install (recommended — gives you `observe` globally)

Requires Go 1.22+. This puts `observe` directly in your `$GOPATH/bin`:

```bash
go install github.com/ctrlaltdean/observer/cmd/observe@latest

# Then from anywhere:
observe 1.2.3.4
observe keys          # configure API keys interactively
```

### Download a pre-built binary

Download the latest release for your platform from the [releases page](https://github.com/ctrlaltdean/observer/releases).

```bash
# Linux / macOS — add to PATH
chmod +x observe-linux-amd64
sudo mv observe-linux-amd64 /usr/local/bin/observe

# Windows — add the directory to your PATH or drop it in C:\Windows\System32
observe-windows-amd64.exe 1.2.3.4
```

### Build from source

```bash
git clone https://github.com/ctrlaltdean/observer
cd observer
go mod tidy
make build-all     # builds dist/observe and dist/observer-server
```

---

## Quick start

1. **Configure API keys interactively:**

   ```bash
   observe keys
   ```

   This opens a menu where you can paste in each key and press `Ctrl+S` to save to `.env`.
   Alternatively copy `.env.example` → `.env` and edit it manually.

2. **Check which sources are active:**

   ```bash
   observe config
   ```

3. **Enrich an observable:**

   ```bash
   observe 1.2.3.4
   observe evil.example.com
   observe https://phishing-site.example.com/login
   observe d41d8cd98f00b204e9800998ecf8427e
   ```

---

## Configuration

All configuration is via environment variables or a `.env` file in the working directory. See [`.env.example`](.env.example) for the full list.

| Variable | Description | Default |
|---|---|---|
| `SHODAN_API_KEY` | Shodan API key | — |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key | — |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | — |
| `OTX_API_KEY` | AlienVault OTX API key | — |
| `IPINFO_TOKEN` | ipinfo.io token (optional — enables privacy data) | — |
| `OBSERVER_API_KEY` | Web server API key (leave empty to disable auth) | — |
| `OBSERVER_PORT` | Web server listen port | `8080` |
| `OBSERVER_LOG_LEVEL` | Log verbosity: debug / info / warn / error | `info` |
| `ENRICHER_TIMEOUT_SECONDS` | Per-source context timeout | `15` |
| `BULK_CONCURRENCY` | Max concurrent goroutines in bulk mode | `5` |

Sources with no API key are automatically disabled. WHOIS and basic ipinfo geo work without keys.

---

## CLI reference

```
observe <observable>                      Enrich a single observable (pretty table)
observe <observable> --format json        JSON output (machine-readable)
observe <observable> --format markdown    Markdown tables (for reports / IRIS notes)
observe <observable> --format csv         Flat CSV (observable,type,source,field,value)
observe <observable> --sources vt,shodan  Run a subset of sources
observer bulk <file>                       Enrich all lines in a file
observer bulk --stdin                      Read observables from stdin (pipe-friendly)
observer version                           Print version
observer config                            Show which sources are configured
```

### Global flags

| Flag | Default | Description |
|---|---|---|
| `--config <file>` | `.env` | Path to a custom .env config file |
| `--format` | `table` | Output format: `table`, `json`, `markdown`, `csv` |
| `--sources` | all | Comma-separated list of sources to run |

### Pipe-friendly mode

When stdout is not a TTY (e.g., piped to `jq` or a file), all color and ANSI formatting is stripped automatically. The `--format json` flag always produces clean JSON regardless of TTY.

```bash
# Pipe to jq
observer 1.2.3.4 --format json | jq '.sources.virustotal.data'

# Bulk from stdin
cat ips.txt | observer bulk --stdin --format json > results.json
```

---

## Server setup

```bash
# With .env file
./observer-server --port 8080 --config .env

# Environment variables only (container / Docker)
SHODAN_API_KEY=xxx VIRUSTOTAL_API_KEY=yyy ./observer-server

# Docker example
docker run -e SHODAN_API_KEY=xxx -e VIRUSTOTAL_API_KEY=yyy \
  -p 8080:8080 observertool/observer-server
```

On startup, the server logs which sources are configured. If `OBSERVER_API_KEY` is not set, it warns that auth is disabled.

Open `http://localhost:8080` in a browser for the web UI.

---

## API reference

### Authentication

If `OBSERVER_API_KEY` is configured, include it in every `/api/*` request (except `/api/health`):

```
X-API-Key: your-key-here
```

### Endpoints

#### `GET /api/health`
Always unauthenticated. Returns server status.

```json
{ "status": "ok", "version": "1.0.0" }
```

#### `GET /api/enrich?q={observable}`
Enrich a single observable.

**Query parameters:**
- `q` — the observable (required)
- `sources` — comma-separated source filter, e.g. `vt,shodan` (optional)

```bash
curl -H "X-API-Key: mykey" \
  "http://localhost:8080/api/enrich?q=1.2.3.4"

curl -H "X-API-Key: mykey" \
  "http://localhost:8080/api/enrich?q=evil.com&sources=virustotal,otx"
```

**Response:** [`EnrichmentResult`](#data-model) object.

#### `POST /api/enrich/bulk`
Enrich multiple observables.

```bash
curl -H "X-API-Key: mykey" \
  -H "Content-Type: application/json" \
  -d '{"observables":["1.2.3.4","evil.com"]}' \
  http://localhost:8080/api/enrich/bulk
```

**Response:**
```json
{
  "count": 2,
  "results": [ ...EnrichmentResult... ]
}
```

#### `GET /api/sources`
List all sources and whether they are configured.

```json
{
  "sources": [
    { "name": "shodan", "configured": true,  "description": "..." },
    { "name": "virustotal", "configured": false, "description": "..." }
  ]
}
```

### Error format

```json
{
  "error": "unsupported observable type: foobar",
  "code": "UNSUPPORTED_TYPE"
}
```

### Data model

```go
EnrichmentResult {
  observable  string
  type        string          // "IPv4" | "IPv6" | "Domain" | "URL" | "MD5" | "SHA1" | "SHA256"
  timestamp   time.Time
  sources     map[string]SourceResult
}

SourceResult {
  name          string
  status        string        // "ok" | "error" | "rate_limited" | "unsupported"
  error_message string        // omitted when empty
  data          map[string]any
  raw_url       string        // link to source UI, omitted when empty
}
```

---

## Source coverage

| Source | IPv4 | IPv6 | Domain | URL | MD5 | SHA1 | SHA256 | Free key? |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Shodan | ✅ | — | ✅¹ | — | — | — | — | ✅ |
| VirusTotal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| AbuseIPDB | ✅ | ✅ | — | — | — | — | — | ✅ |
| WHOIS | ✅ | ✅ | ✅ | ✅² | — | — | — | No key |
| AlienVault OTX | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| ipinfo.io | ✅ | ✅ | — | — | — | — | — | Optional |

¹ Shodan resolves the domain to an IP first.  
² WHOIS extracts the domain from the URL, then queries WHOIS for that domain.

---

## Adding an enricher

1. Create `internal/enricher/mysource.go` implementing the `Enricher` interface:

   ```go
   type MySourceEnricher struct { /* ... */ }
   
   func (m *MySourceEnricher) Name() string { return "mysource" }
   
   func (m *MySourceEnricher) SupportedTypes() []detect.ObservableType {
       return []detect.ObservableType{detect.TypeIPv4}
   }
   
   func (m *MySourceEnricher) Enrich(ctx context.Context, observable string, oType detect.ObservableType) (*model.SourceResult, error) {
       // ... call API, return SourceResult
   }
   ```

2. Add a constructor call in `internal/runner/runner.go` `buildEnrichers()`:

   ```go
   if cfg.MySourceAPIKey != "" {
       list = append(list, enricher.NewMySource(cfg.MySourceAPIKey))
   }
   ```

3. Add the key to `config/config.go` and `.env.example`.

4. Write a test in `internal/enricher/mysource_test.go` using `httptest.NewServer`.

---

## API key signup links

| Source | Sign-up URL |
|---|---|
| Shodan | https://account.shodan.io/register |
| VirusTotal | https://www.virustotal.com/gui/join-us |
| AbuseIPDB | https://www.abuseipdb.com/register |
| AlienVault OTX | https://otx.alienvault.com/ |
| ipinfo.io | https://ipinfo.io/signup |

---

## License

```
SPDX-License-Identifier: Apache-2.0
```

Copyright (c) 2026 FLINTEK LLC.

Observer is licensed under the **Apache License, Version 2.0**. You may obtain a
copy of the License at <http://www.apache.org/licenses/LICENSE-2.0>. See the
[`LICENSE`](LICENSE) file in the project root for the full text.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied.
