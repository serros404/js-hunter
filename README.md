# js-hunter

Pipeline de recon automatizado de arquivos JavaScript para bug bounty, focada em descoberta de vulnerabilidades de **IDOR** (Insecure Direct Object Reference) e **Broken Access Control (BAC)**.

Roda 100% via Docker — sem instalar nenhuma ferramenta localmente.

> **Uso ético e legal**: use apenas em programas de bug bounty que você está autorizado a testar ou em ambientes de lab locais. Nunca teste alvos sem autorização explícita.

---

## O que faz

Dada uma URL alvo ou um programa com scope definido, o js-hunter:

1. **Coleta** todas as URLs de arquivos `.js` acessíveis (katana, gau, waybackurls)
2. **Extrai** endpoints, referências de API e secrets de cada JS (LinkFinder, trufflehog, regex customizado)
3. **Classifica** cada finding por risco (CRITICAL / HIGH / MEDIUM / LOW) com base em padrões de IDOR/BAC
4. **Gera** três outputs prontos: relatório Markdown, JSON estruturado e lista de URLs para o Burp Suite

---

## Ferramentas incluídas

| Ferramenta | Versão | Função |
|---|---|---|
| katana | v1.5.0 | Crawler ativo de JS (suporta headless Chrome) |
| gau | v2.2.4 | Coleta URLs históricas (AlienVault OTX, Wayback, Common Crawl) |
| waybackurls | latest | Coleta URLs do Wayback Machine |
| subfinder | v2.13.0 | Enumeração de subdomínios |
| httpx | v1.9.0 | Verifica hosts ativos |
| LinkFinder | latest | Extrai endpoints de arquivos JS |
| trufflehog | v3.95.2 | Detecta secrets e credenciais expostas |

---

## Pré-requisitos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) instalado e rodando
- Windows, macOS ou Linux

**Nenhuma dependência local além do Docker.**

---

## Instalação

```bash
git clone https://github.com/serros404/js-hunter.git
cd js-hunter
docker compose -f docker/docker-compose.yml build
```

O build leva alguns minutos na primeira vez — baixa e compila todas as ferramentas dentro da imagem.

---

## Modos de uso

O js-hunter pode ser usado de duas formas:

| Modo | Requisito | Como funciona |
|---|---|---|
| **Standalone (CLI)** | Só Docker | Você digita os comandos manualmente no terminal |
| **Com Claude Code** | Docker + Claude Code CLI | Você fala em linguagem natural e o Claude monta e executa o comando |

---

## Modo Standalone — só Docker, sem Claude

### Instalação

```bash
git clone https://github.com/serros404/js-hunter.git
cd js-hunter
docker compose -f docker/docker-compose.yml build
```

### Uso básico

```bash
# Alvo direto
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com \
  --mode moderate

# Programa de bug bounty com scope configurado
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --program nome-do-programa \
  --mode moderate

# Com cookie de sessão (autenticado)
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com \
  --mode moderate \
  --cookie "session=abc123; csrf=xyz"

# Com Bearer token
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com \
  --mode moderate \
  --header "Authorization: Bearer eyJ..."

# Modo passivo (zero contato com o alvo)
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com \
  --mode passive

# Com enumeração de subdomínios
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --program nome-do-programa \
  --mode moderate \
  --enumerate-subs
```

### Lab com Juice Shop (standalone)

```bash
# Sobe o Juice Shop
docker compose -f docker/docker-compose.dev.yml up juice-shop -d

# Roda o js-hunter contra ele
docker compose -f docker/docker-compose.dev.yml run --rm js-hunter \
  --target juice-shop:3000 \
  --mode moderate \
  --no-scope-check
```

Os resultados ficam em `output/<alvo>/<timestamp>/report.md`.

---

## Modo Claude Code — linguagem natural

O Claude Code é o CLI oficial da Anthropic. Com ele instalado, você faz recon conversando — o Claude interpreta o que você quer, monta o comando correto e executa.

### Instalação do Claude Code

```bash
npm install -g @anthropic-ai/claude-code
claude
```

Mais detalhes em [claude.ai/code](https://claude.ai/code).

### Como usar com Claude Code

Com o Claude Code aberto na pasta do projeto, basta digitar em português:

```
roda js-hunter no app.exemplo.com modo moderate
```

```
js-hunter no meu-programa com enum de subs
```

```
testa no juice shop
```

```
roda agressivo no meu-programa autenticado, cookie session=abc123
```

```
js-hunter passivo no exemplo.com
```

O Claude vai:
1. Verificar se o Docker está rodando
2. Verificar se a imagem existe (e buildar se necessário)
3. Confirmar autorização se for um alvo real
4. Montar e executar o comando correto
5. Apresentar o resumo dos findings após a execução

### Exemplos de comandos aceitos pelo Claude

| Você diz | Comando gerado |
|---|---|
| `"roda js-hunter no meu-programa"` | `--program meu-programa --mode moderate` |
| `"js-hunter no app.exemplo.com modo passivo"` | `--target app.exemplo.com --mode passive` |
| `"roda agressivo com enum de subs no meu-programa"` | `--program meu-programa --mode aggressive --enumerate-subs` |
| `"autenticado, cookie session=abc"` | adiciona `--cookie "session=abc"` |
| `"testa no juice shop"` | usa `docker-compose.dev.yml` com `--target juice-shop:3000 --no-scope-check` |

---

## Como usar

### Opção 1 — Lab local com OWASP Juice Shop

O Juice Shop já está integrado no projeto. Ideal para testar e aprender antes de usar em alvos reais.

```bash
# Sobe o Juice Shop
docker compose -f docker/docker-compose.dev.yml up juice-shop -d

# Roda o js-hunter contra ele
docker compose -f docker/docker-compose.dev.yml run --rm js-hunter \
  --target juice-shop:3000 \
  --mode moderate \
  --no-scope-check
```

Acesse `http://localhost:3000` no browser para ver o Juice Shop durante o teste.

### Opção 2 — Alvo direto

```bash
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com \
  --mode moderate
```

### Opção 3 — Programa de bug bounty com scope

```bash
# 1. Configure o scope (veja seção abaixo)
# 2. Rode:
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --program nome-do-programa \
  --mode moderate
```

---

## Todos os parâmetros

| Flag | Descrição | Padrão |
|---|---|---|
| `--target <host>` | Alvo único (ex: `app.exemplo.com`, `localhost:3000`) | — |
| `--program <nome>` | Programa com scope em `targets/programs/<nome>/scope.yml` | — |
| `--mode <modo>` | `passive` / `moderate` / `aggressive` | `moderate` |
| `--enumerate-subs` | Enumera subdomínios antes da coleta (requer `--program` com wildcards no scope) | desativado |
| `--no-scope-check` | Desativa validação de scope — **apenas em labs locais** | desativado |
| `--cookie "<valor>"` | Cookie de sessão para testes autenticados | — |
| `--header "<valor>"` | Header de autenticação (ex: `Authorization: Bearer <token>`) | — |

### Modos de operação

| Modo | Ferramentas ativas | Toca o alvo? | Indicado para |
|---|---|---|---|
| `passive` | gau + waybackurls | Não | Recon inicial, evitar detecção |
| `moderate` | katana depth=2 + gau + waybackurls | Sim, baixo impacto | Uso padrão |
| `aggressive` | katana depth=5 headless + gau + waybackurls | Sim, maior impacto | Alvos com SPA / muito JS dinâmico |

---

## Configurando um programa de bug bounty

```bash
cp -r targets/programs/_template targets/programs/nome-do-programa
```

Edite `targets/programs/nome-do-programa/scope.yml`:

```yaml
program: "Nome do Programa"
platform: "HackerOne"       # HackerOne | BugCrowd | Intigriti | YesWeHack | Private
handle: "nome-do-programa"

in_scope:
  domains:
    - "*.exemplo.com"       # cobre sub.exemplo.com — NÃO cobre exemplo.com
    - "exemplo.com"         # root precisa ser listado separadamente
    - "app.exemplo.io"

out_of_scope:
  domains:
    - "blog.exemplo.com"
    - "status.exemplo.com"
  paths:
    - "/wp-admin/*"

metadata:
  last_updated: "2026-04-24"
  max_severity: "Critical"
  safe_harbor: true
```

O scope guard valida **todas** as URLs coletadas contra esse arquivo antes de qualquer requisição ativa. URLs fora do scope são descartadas e salvas em `out_of_scope_refs.txt` como intel passivo.

---

## Testes autenticados

**Com cookie de sessão:**

1. Faça login no alvo no browser
2. Abra DevTools (F12) → aba Network → clique em qualquer requisição autenticada → aba Headers
3. Copie o valor completo do campo `Cookie:`

```bash
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com \
  --mode moderate \
  --cookie "session=abc123; csrf=xyz789"
```

**Com Bearer token:**

```bash
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com \
  --mode moderate \
  --header "Authorization: Bearer eyJ..."
```

---

## Outputs

Cada execução gera uma pasta com timestamp:

```
output/<alvo ou programa>/<YYYY-MM-DD_HHMMSS>/
├── report.md              ← leia primeiro — findings ordenados por risco
├── findings.json          ← todos os findings estruturados
├── burp_import.txt        ← URLs para Burp Suite (Target > Site Map > Load URLs)
├── out_of_scope_refs.txt  ← domínios externos encontrados nos JS (intel passivo)
└── raw/
    ├── js_urls.txt            ← JS files coletados in-scope
    ├── endpoints_raw.jsonl    ← endpoints antes do scoring
    ├── secrets.jsonl          ← findings do trufflehog
    └── dom_sinks.jsonl        ← usos de DOM sinks perigosos
```

### Como interpretar o report.md

| Tier | Score | Critério |
|---|---|---|
| **CRITICAL** | ≥ 5 | Múltiplos indicadores: padrão HIGH + método mutante (DELETE/PUT/PATCH) + aparece em 2+ JS files |
| **HIGH** | ≥ 3 | Padrão de IDOR/BAC de alto risco ou método mutante isolado |
| **MEDIUM** | ≥ 1 | Padrão de risco moderado |
| **LOW** | 0 | Sem indicadores — incluso no JSON, omitido do report principal |

Os findings são **ponto de partida para análise manual** — confirme no Burp Suite antes de reportar.

---

## Exemplos completos

```bash
# Lab — Juice Shop modo agressivo
docker compose -f docker/docker-compose.dev.yml run --rm js-hunter \
  --target juice-shop:3000 --mode aggressive --no-scope-check

# Programa com enum de subdomínios
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --program meu-programa --mode moderate --enumerate-subs

# Autenticado com cookie + modo agressivo
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target app.exemplo.com --mode aggressive \
  --cookie "session=abc123; csrf=xyz"

# Passivo — zero contato com o alvo
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target exemplo.com --mode passive

# Programa com autenticação Bearer
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --program meu-programa --mode moderate \
  --header "Authorization: Bearer eyJ..."
```

---

## Arquitetura do pipeline

```
Fase 0  DISCOVER   subfinder + httpx       → enumera subdomínios (--enumerate-subs)
Fase 1  COLLECT    katana + gau + wayback  → coleta URLs de .js files
Fase 2  EXTRACT    LinkFinder + trufflehog → extrai endpoints e secrets
Fase 3  CLASSIFY   scoring model Python    → prioriza por risco IDOR/BAC
Fase 4  REPORT     Jinja2                  → report.md + findings.json + burp_import.txt
```

### Scoring model (Fase 3)

```
Pattern HIGH match          → +3 pts
Pattern MEDIUM match        → +1 pt
Método DELETE/PUT/PATCH     → +2 pts
Aparece em 2+ JS files      → +1 pt (confiança)
Secret verificado           → CRITICAL direto
Secret não verificado       → HIGH direto
```

---

## Estrutura do projeto

```
js-hunter/
├── docker/
│   ├── Dockerfile              ← imagem multi-stage (~todos os tools compilados)
│   ├── docker-compose.yml      ← uso com alvos reais
│   └── docker-compose.dev.yml  ← lab com Juice Shop integrado
├── targets/
│   └── programs/
│       └── _template/
│           └── scope.yml       ← copie para criar um novo programa
├── .claude/skills/js-hunter/
│   ├── scripts/
│   │   ├── run.sh              ← entry point do container
│   │   ├── 00_discover.sh      ← Fase 0: enumeração de subdomínios
│   │   ├── 01_collect.sh       ← Fase 1: coleta de JS URLs
│   │   ├── 02_extract.py       ← Fase 2: extração de endpoints e secrets
│   │   ├── 03_classify.py      ← Fase 3: scoring e classificação por risco
│   │   ├── 04_report.py        ← Fase 4: geração dos relatórios
│   │   └── scope_guard.py      ← validador de scope
│   ├── regex/
│   │   ├── idor_patterns.json  ← padrões regex para IDOR
│   │   ├── bac_patterns.json   ← padrões regex para BAC
│   │   ├── secret_patterns.json
│   │   └── dom_sinks.json      ← DOM sinks perigosos
│   └── templates/
│       └── report.md.j2        ← template Jinja2 do relatório
├── output/                     ← resultados (gitignored)
└── .gitignore
```

---

## Segurança — o que NÃO vai para o GitHub

O `.gitignore` já bloqueia:

| O que | Por quê |
|---|---|
| `output/` | Resultados de recon com dados de alvos reais |
| `targets/programs/*/` | Seus scopes reais (apenas `_template` é público) |
| `.env`, `*.cookie`, `*.token` | Credenciais e sessões |

**Nunca passe cookies ou tokens como argumento em terminais compartilhados.** Use variáveis de ambiente:

```bash
export COOKIE="session=abc123"
docker compose -f docker/docker-compose.yml run --rm \
  -e COOKIE js-hunter --target app.exemplo.com
```

---

## Troubleshooting

| Problema | Causa provável | Solução |
|---|---|---|
| `0 JS URLs coletadas` | Alvo não acessível ou JS dinâmico demais | Tente `--mode aggressive` (usa Chromium headless) |
| `katana: not found` | Imagem desatualizada | `docker compose build --no-cache` |
| `scope.yml not found` | Programa não configurado | Copie e edite `targets/programs/_template/` |
| Cookie expirado | JWT/session com TTL | Faça login novamente e copie o novo cookie |
| `0 resultados` no Juice Shop | Juice Shop não está rodando | `docker compose -f docker/docker-compose.dev.yml up juice-shop -d` |

---

## Subindo no GitHub

### Primeira vez

```bash
# 1. Inicializa o git na pasta do projeto
git init
git add .

# Confirme que output/ e targets/programs/*/ NÃO aparecem no status
git status

# 2. Commit inicial
git commit -m "feat: js-hunter v1.0 — JS recon pipeline for IDOR/BAC bug bounty"

# 3. Cria o repositório público e faz o push (requer gh CLI instalado)
gh repo create serros404/js-hunter --public --source=. --remote=origin --push
```

**Sem o `gh` CLI:** crie o repositório em [github.com/new](https://github.com/new) com o nome `js-hunter`, depois:

```bash
git remote add origin https://github.com/serros404/js-hunter.git
git branch -M main
git push -u origin main
```

### Atualizações futuras

```bash
git add .
git commit -m "descrição da mudança"
git push
```

### O que o .gitignore já protege

| Bloqueado | Por quê |
|---|---|
| `output/` | Resultados de recon com dados de alvos reais |
| `targets/programs/*/` | Seus scopes reais (só o `_template` é público) |
| `.env`, `*.cookie`, `*.token` | Credenciais e sessões |
| `.claude/settings.local.json` | Configuração local do Claude Code |

---

## Licença

MIT — livre para uso pessoal e entre amigos. Não use contra sistemas sem autorização explícita.
