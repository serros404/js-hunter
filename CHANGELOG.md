# Changelog

All notable changes to **js-hunter** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security
- **Command injection fix** (`01_collect.sh`) — `AUTH_FLAGS` convertido de string para array bash; `$COOKIE` e `$AUTH_HEADER` não são mais interpolados diretamente em strings, eliminando possibilidade de injeção de comandos via valores de cookie/header
- **SSRF mitigation** (`02_extract.py`) — adicionada `_is_safe_url()` que bloqueia requisições para IPs de cloud metadata (`169.254.169.254`, `100.100.100.200`) e loopback (`127.0.0.1`, `localhost`, `::1`); RFC1918 deliberadamente não bloqueado para não quebrar testes em redes internas
- **Scope bypass via URL encoding** (`scope_guard.py`) — `path` agora é URL-decoded (`unquote()`) antes da comparação com `out_of_scope.paths`, evitando que `%2f` bypass o scope check

### Added
- **`--help` / `-h`** (`run.sh`) — flag de help agora imprime todas as opções e sai com código 0; antes retornava `[ERROR] Flag desconhecida`
- **Pattern `/me` em `bac_patterns.json`** — detecta `/api/v1/users/me` e variantes; endpoint clássico de BAC quando testado com token de outro usuário
- **`dangerouslySetInnerHTML` em `dom_sinks.json`** — sink React de XSS ausente da lista; agora coberto na categoria `direct_html_write`

### Fixed
- **`burp_import.txt` agora inclui paths relativos** (`04_report.py`) — endpoints como `/admin/` e `/api/users` são resolvidos contra `http://<TARGET>` antes de escrever no arquivo; anteriormente o filtro `startswith("http")` os excluía silenciosamente
- **FP em `base64_id_param`** (`idor_patterns.json`) — pattern anterior aceitava qualquer string alfanumérica de 16+ chars (ex: `nftMintChallenge`); novo pattern exige presença de `=` (padding) ou `+`/`/` (chars reais de base64)
- **Hostname errado no exemplo Juice Shop** (`SKILL.md`) — `localhost:3000` corrigido para `juice-shop:3000` no contexto Docker (o container não resolve `localhost` para o serviço juice-shop na rede Docker)

---

## [1.1.0] - 2026-04-27

### Added
- **Hardcoded URL extraction** — new `extract_hardcoded_urls()` scans JS string literals for `http://`, `https://` and `localhost:PORT/` patterns, replicating the DevTools Network filter technique used manually by hunters
- **Relative API path extraction** — detects `/api/`, `/rest/`, `/v1/`, `/graphql/`, `/admin/` and similar paths hardcoded as string literals in JS
- **Noise filter** (`is_noise_endpoint()`) — automatically drops framework noise before classification:
  - Static assets (`.js`, `.css`, `.map`, `.woff`, `.svg`, etc.)
  - MIME type strings masquerading as paths (`text/x-python`, `application/json`, CodeMirror language modes, etc.)
  - Angular/webpack internals (`@angular`, `__webpack`, `.component`, `.module`, `hot-update`, etc.)
  - Pure numeric paths (`/10`, `/40`, `/160`)
  - Date format strings (`/M/d/yy`)
  - Fragment-only SPA routes (`/#/wallet`)
- **Normalized dedup** — `http://target.com/api/users` and `/api/users` are now treated as the same endpoint and deduplicated correctly
- **REST surface scoring** — endpoints matching `/api/`, `/rest/`, `/v1/`, `/graphql/` are automatically promoted to MEDIUM even without an explicit IDOR/BAC pattern match
- **Sensitive route scoring** — routes like `/data-export`, `/file-upload`, `/payment`, `/orders`, `/wallet`, `/admin`, `/accounting`, `/snippets` are promoted to MEDIUM automatically
- **Hardcoded URL rescoring** — hardcoded URLs (`matched_by: hardcoded_string`) are rescored against all IDOR/BAC patterns on their actual content, not just their metadata label

### Changed
- `score_endpoint()` now skips the generic `pattern_name`-based score for hardcoded strings and applies the full IDOR/BAC pattern suite instead — a hardcoded `/rest/admin/users/123` now correctly scores HIGH
- Added `urllib.parse.urlparse` import to `03_classify.py`

### Fixed
- Duplicate entries for the same endpoint appearing as both relative path and absolute URL (e.g. `/admin/` and `http://target.com/admin/` both showing as HIGH)

### Results (vs v1.0.0 on OWASP Juice Shop)
| Metric | v1.0.0 | v1.1.0 |
|---|---|---|
| Total endpoints | 400 | 145 |
| LOW (noise) | 396 | 84 |
| MEDIUM (real surfaces) | 2 | 59 |
| HIGH | 2 | 2 |

---

## [1.0.0] - 2026-04-24

### Added
- **4-phase pipeline**: COLLECT → EXTRACT → CLASSIFY → REPORT
- **Phase 0 (DISCOVER)** — subfinder + httpx for subdomain enumeration (`--enumerate-subs`)
- **Phase 1 (COLLECT)** — katana (active crawler with Chromium headless support), gau and waybackurls running in parallel; three modes: `passive`, `moderate` (default), `aggressive`
- **Phase 2 (EXTRACT)** — LinkFinder for endpoint extraction, trufflehog for secret detection, custom regex for DOM sinks (`innerHTML`, `postMessage`, `localStorage`, etc.)
- **Phase 3 (CLASSIFY)** — Python scoring model with IDOR and BAC pattern libraries (`idor_patterns.json`, `bac_patterns.json`); four tiers: CRITICAL / HIGH / MEDIUM / LOW
- **Phase 4 (REPORT)** — Jinja2 templates generating `report.md`, `findings.json` and `burp_import.txt`
- **Scope guard** — validates every collected URL against `scope.yml` before any active request; out-of-scope references saved as passive intel
- **Multi-stage Dockerfile** — Go tools (katana, gau, waybackurls, subfinder, httpx), Python tools (LinkFinder, Jinja2) and trufflehog compiled in separate stages; final image is self-contained
- **`docker-compose.dev.yml`** — local lab environment with OWASP Juice Shop pre-integrated for testing
- **IDOR patterns**: numeric ID in path, UUID in path, ID query parameters, action endpoints with sequential IDs, nested resource IDs, base64 ID params, template literals with object references
- **BAC patterns**: admin paths, internal APIs, role/permission mutation endpoints, DELETE on user resources, bulk operations, impersonation endpoints, sensitive config and export endpoints
- **Claude Code skill** (`SKILL.md`) — natural language interface; "roda js-hunter no app.exemplo.com modo aggressive" triggers the full pipeline
- **Authenticated scanning** — `--cookie` and `--header` flags pass session credentials to katana and the extractor

[Unreleased]: https://github.com/serros404/js-hunter/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/serros404/js-hunter/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/serros404/js-hunter/releases/tag/v1.0.0
