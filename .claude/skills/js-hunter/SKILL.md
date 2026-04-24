# Skill: js-hunter

Recon pipeline de JS files para bug bounty, focada em IDOR e Broken Access Control.
Executa via Docker e retorna findings priorizados por risco.

## Quando ativar esta skill

Ativar quando o usuário mencionar qualquer combinação de:
- "js-hunter", "js hunter", "hunt js", "recon js"
- "roda [em/no/na] <domínio ou programa>"
- "js files", "endpoints", "IDOR", "BAC" + contexto de bug bounty/recon

## Parâmetros extraídos da conversa

| Parâmetro | Como identificar | Valor padrão |
|-----------|-----------------|--------------|
| PROGRAM   | nome de programa ("hackerone-exemplo", "bugcrowd-acme") | — |
| TARGET    | domínio ou IP ("app.exemplo.com", "localhost:3000") | — |
| MODE      | "passivo/passive", "moderado/moderate", "agressivo/aggressive" | moderate |
| ENUMERATE_SUBS | "com enum de subs", "enumera subdomínios" | false |
| COOKIE    | "autenticado com cookie X" | — |
| AUTH_HEADER | "com header Authorization: Bearer X" | — |

**Regra:** Se o usuário mencionar programa → usa `--program`. Se mencionar só domínio → usa `--target`.

## Pré-condições — verificar ANTES de rodar

### 1. Docker está rodando?
```bash
docker info > /dev/null 2>&1 && echo "OK" || echo "Docker não está rodando"
```
Se falhar: pedir para o usuário iniciar o Docker Desktop.

### 2. Imagem existe?
```bash
docker image inspect js-hunter:latest > /dev/null 2>&1 && echo "exists" || echo "missing"
```
Se não existir: fazer build primeiro.
```bash
docker compose -f /caminho/para/js-hunter/docker/docker-compose.yml build
```

### 3. Scope válido? (só para --program)
```bash
test -f targets/programs/<PROGRAM>/scope.yml && echo "OK" || echo "MISSING"
```
Se não existir: avisar o usuário para criar o scope file antes de rodar.

### 4. Para --target com domínio real (não localhost/lab): confirmar autorização
> "Confirma que você tem autorização para testar <TARGET>? (bug bounty / pentest autorizado)"

## Sequência de execução

### Build (se necessário)
```bash
cd /caminho/para/js-hunter
docker compose -f docker/docker-compose.yml build
```

### Execução com --program
```bash
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --program <PROGRAM> \
  --mode <MODE> \
  [--enumerate-subs] \
  [--cookie "<COOKIE>"] \
  [--header "<AUTH_HEADER>"]
```

### Execução com --target (lab/teste)
```bash
docker compose -f docker/docker-compose.yml run --rm js-hunter \
  --target <TARGET> \
  --mode <MODE> \
  --no-scope-check \
  [--cookie "<COOKIE>"] \
  [--header "<AUTH_HEADER>"]
```

### Execução com Juice Shop (dev)
```bash
# Sobe o Juice Shop se não estiver rodando
docker compose -f docker/docker-compose.dev.yml up juice-shop -d

# Roda o js-hunter
docker compose -f docker/docker-compose.dev.yml run --rm js-hunter \
  --target localhost:3000 \
  --mode moderate \
  --no-scope-check
```

## Após a execução

1. Localizar o diretório de output:
   - `output/<PROGRAM ou TARGET>/<timestamp>/`

2. Ler o report com o Read tool:
   - `output/.../report.md`

3. Apresentar ao usuário:
   - Contagem por severity (CRITICAL/HIGH/MEDIUM)
   - Top 3-5 findings mais críticos com endpoint + razão
   - Caminho dos 3 arquivos gerados
   - Mencionar se há out_of_scope_refs.txt com conteúdo relevante

4. NÃO fazer análise automática dos findings — o usuário faz a análise manual.
   Apenas apresentar o sumário e os caminhos.

## Mensagens de erro comuns

| Erro | Causa | Solução |
|------|-------|---------|
| `Docker not running` | Docker Desktop fechado | Pedir para abrir |
| `scope.yml not found` | Programa não configurado | Criar targets/programs/<name>/scope.yml |
| `No JS URLs found` | Alvo não acessível ou sem JS | Verificar conectividade, tentar modo passive |
| `katana: permission denied` | Script sem permissão | `chmod +x scripts/*.sh` dentro do container |

## Exemplos de invocação do usuário → comando gerado

| Usuário diz | Comando |
|-------------|---------|
| "roda js-hunter no hackerone-exemplo" | `--program hackerone-exemplo --mode moderate` |
| "js-hunter no exemplo.com modo passivo" | `--target exemplo.com --mode passive` |
| "roda agressivo com enum de subs no bugcrowd-acme" | `--program bugcrowd-acme --mode aggressive --enumerate-subs` |
| "js-hunter autenticado, cookie session=abc" | adiciona `--cookie "session=abc"` |
| "testa no juice shop" | usa docker-compose.dev.yml com `--target localhost:3000 --no-scope-check` |
