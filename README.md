<div align="center">

<h1>js-hunter</h1>

<p>JS recon pipeline for IDOR & Broken Access Control bug bounty hunting</p>

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](docker/Dockerfile)
[![Python](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)](docker/Dockerfile)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](#)

</div>

---

**js-hunter** coleta todos os arquivos `.js` de um alvo, extrai endpoints e secrets hardcoded — incluindo URLs em string literals (o que você faria filtrando por `http`/`https`/`localhost` no DevTools) — e classifica cada finding por risco de IDOR/BAC. Tudo via Docker, sem instalar nada localmente.

> Use apenas em programas de bug bounty nos quais você está autorizado. Nunca teste alvos sem autorização explícita.

---

## Features

- **Coleta multi-fonte** — katana (crawler ativo + Chromium headless), gau e waybackurls em paralelo
- **Extração de hardcoded URLs** — varre string literals por `http://`, `https://` e `localhost:PORT/` (replica filtro do DevTools)
- **Filtro de ruído** — elimina MIME types, paths de framework Angular/webpack e assets automaticamente
- **Dedup normalizado** — `/api/users` e `https://target.com/api/users` são tratados como o mesmo endpoint
- **Scoring IDOR/BAC** — padrões regex para IDs numéricos, UUIDs, template literals, métodos mutantes (DELETE/PUT/PATCH), paths de admin/internal
- **Detecção de secrets** — trufflehog integrado, verifica automaticamente se o secret está ativo
- **Scope guard** — valida cada URL contra o `scope.yml` do programa antes de qualquer requisição ativa
- **3 outputs prontos** — `report.md` priorizado, `findings.json` estruturado, `burp_import.txt` para o Burp Suite

---

## Ferramentas incluídas

| Ferramenta | Função |
|---|---|
| [katana](https://github.com/projectdiscovery/katana) | Crawler ativo de JS (suporta Chromium headless) |
| [gau](https://github.com/lc/gau) | URLs históricas — AlienVault OTX, Wayback, Common Crawl |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | URLs do Wayback Machine |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Enumeração de subdomínios |
| [httpx](https://github.com/projectdiscovery/httpx) | Verificação de hosts ativos |
| [LinkFinder](https://github.com/GerbenJavado/LinkFinder) | Extração de endpoints de JS |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Detecção e verificação de secrets |

---

## Instalação

**Requisito:** [Docker Desktop](https://www.docker.com/products/docker-desktop/)

```bash
git clone https://github.com/serros404/js-hunter.git
cd js-hunter
docker compose -f docker/docker-compose.yml build
```

O build leva alguns minutos na primeira vez — compila todos os Go tools e instala as dependências Python dentro da imagem.

---

## Uso

### Alvo direto

```bash
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com \
  --mode moderate
```

### Programa de bug bounty com scope

```bash
# 1. Configure o scope
cp -r targets/programs/_template targets/programs/meu-programa
# edite targets/programs/meu-programa/scope.yml

# 2. Rode
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --program meu-programa \
  --mode moderate
```

### Autenticado (cookie ou Bearer token)

```bash
# Cookie de sessão
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com --mode moderate \
  --cookie "session=abc123; csrf=xyz"

# Bearer token
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com --mode moderate \
  --header "Authorization: Bearer eyJ..."
```

### Lab local com OWASP Juice Shop

```bash
docker compose -f docker/docker-compose.dev.yml up juice-shop -d
docker compose -f docker/docker-compose.dev.yml run --rm js-hunter \
  --target juice-shop:3000 --no-scope-check
```

---

## Parâmetros

| Flag | Descrição | Padrão |
|---|---|---|
| `--target <host>` | Alvo direto (`app.exemplo.com`, `localhost:3000`) | — |
| `--program <nome>` | Programa com scope em `targets/programs/<nome>/scope.yml` | — |
| `--mode <modo>` | `passive` / `moderate` / `aggressive` | `moderate` |
| `--enumerate-subs` | Enumera subdomínios antes da coleta (requer `--program`) | desativado |
| `--no-scope-check` | Desativa validação de scope — **apenas em labs locais** | desativado |
| `--cookie "<valor>"` | Cookie de sessão para testes autenticados | — |
| `--header "<valor>"` | Header de autenticação (`Authorization: Bearer <token>`) | — |

### Modos de operação

| Modo | Toca o alvo? | Indicado para |
|---|---|---|
| `passive` | Não | Recon inicial, evitar detecção |
| `moderate` | Sim, baixo impacto | Uso padrão |
| `aggressive` | Sim, maior impacto | SPAs com muito JS dinâmico |

---

## Outputs

```
output/<alvo>/<YYYY-MM-DD_HHMMSS>/
├── report.md              ← leia aqui — findings ordenados por risco
├── findings.json          ← todos os findings estruturados
├── burp_import.txt        ← URLs para Burp Suite (Target > Site Map > Load URLs)
├── out_of_scope_refs.txt  ← domínios externos encontrados nos JS (intel passivo)
└── raw/
    ├── js_urls.txt
    ├── endpoints_raw.jsonl
    ├── secrets.jsonl
    └── dom_sinks.jsonl
```

### Scoring model

| Tier | Score | Critério |
|---|---|---|
| **CRITICAL** | ≥ 5 | Múltiplos indicadores: padrão HIGH + método mutante + 2+ JS files |
| **HIGH** | ≥ 3 | Padrão IDOR/BAC de alto risco ou método mutante isolado |
| **MEDIUM** | ≥ 1 | Padrão de risco moderado, endpoint REST/API ou rota sensível |
| **LOW** | 0 | Sem indicadores — incluso no JSON, omitido do report principal |

---

## Configurando um programa

Edite `targets/programs/meu-programa/scope.yml`:

```yaml
program: "Nome do Programa"
platform: "HackerOne"   # HackerOne | BugCrowd | Intigriti | YesWeHack | Private
handle: "meu-programa"

in_scope:
  domains:
    - "*.exemplo.com"
    - "exemplo.com"

out_of_scope:
  domains:
    - "blog.exemplo.com"
  paths:
    - "/wp-admin/*"

metadata:
  last_updated: "2026-04-27"
  max_severity: "Critical"
  safe_harbor: true
```

O scope guard valida todas as URLs coletadas antes de qualquer requisição ativa. URLs fora do scope vão para `out_of_scope_refs.txt` como intel passivo.

---

## Pipeline

```
Fase 0  DISCOVER   subfinder + httpx       → enumera subdomínios (--enumerate-subs)
Fase 1  COLLECT    katana + gau + wayback  → coleta URLs de .js files
Fase 2  EXTRACT    LinkFinder + trufflehog → extrai endpoints, hardcoded URLs e secrets
Fase 3  CLASSIFY   scoring model Python    → prioriza por risco IDOR/BAC
Fase 4  REPORT     Jinja2                  → report.md + findings.json + burp_import.txt
```

---

## Troubleshooting

| Problema | Solução |
|---|---|
| `0 JS URLs coletadas` | Tente `--mode aggressive` (usa Chromium headless) |
| `katana: not found` | `docker compose build --no-cache` |
| `scope.yml not found` | Copie e edite `targets/programs/_template/` |
| Cookie expirado | Faça login novamente e copie o novo cookie |
| Juice Shop não responde | `docker compose -f docker/docker-compose.dev.yml up juice-shop -d` |

---

## Licença

MIT — livre para uso pessoal e profissional em programas de bug bounty autorizados.
