#!/usr/bin/env bash

BASE_DIR="$(pwd)"

# 📌 Definir subdiretórios
HTTPX_DIR="$BASE_DIR/httpx"
DIRSEARCH_DIR="$BASE_DIR/dirsearch"
URLS_DIR="$BASE_DIR/urls"
GITHUB_DIR="$BASE_DIR/github"
REPORT_FILE="$BASE_DIR/relatorio.txt"

# 📌 Criar diretórios necessários
mkdir -p "$URLS_DIR" "$HTTPX_DIR" "$DIRSEARCH_DIR" "$GITHUB_DIR"

# 📌 Verificar dependências
check_dependency() {
    command -v "$1" >/dev/null 2>&1 || { echo "❌ Erro: $1 não encontrado. Instale antes de continuar."; exit 1; }
}

# 📌 Ferramentas obrigatórias
TOOLS=("waybackurls" "gau" "httpx" "gospider" "dirsearch" "hakrawler")

for tool in "${TOOLS[@]}"; do
    check_dependency "$tool"
done

# 📌 Verificar argumento de entrada
if [ -z "$1" ]; then
    echo "❌ Uso: $0 <arquivo-com-dominios-ou-URL-unica>"
    exit 1
fi

# 📌 Detectar se argumento é arquivo ou URL única
if [[ -f "$1" ]]; then
    INPUT_FILE="$1"
elif [[ "$1" =~ ^https?:// ]]; then
    INPUT_FILE=$(mktemp)
    echo "$1" > "$INPUT_FILE"
else
    echo "❌ Argumento inválido. Deve ser uma URL válida ou um arquivo com URLs/domínios."
    exit 1
fi

# 📌 Função de log
log() {
    echo -e "[ $(date +'%Y-%m-%d %H:%M:%S') ] $1"
}

# 📌 Gerar User-Agent aleatório
USER_AGENT_LIST=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
                 "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
                 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36")

RANDOM_UA="${USER_AGENT_LIST[$RANDOM % ${#USER_AGENT_LIST[@]}]}"

# 📌 Coletar URLs
log "🔎 Coletando URLs..."
{
    cat "$INPUT_FILE" | waybackurls > "$URLS_DIR/waybackurls.txt" &
    grep -E '^[a-zA-Z0-9._-]+' "$INPUT_FILE" | gau --providers otx,urlscan --blacklist ttf,woff,svg,png --timeout 30 > "$URLS_DIR/gau.txt" &

    # Limpar e preparar arquivo para waymore
    temp_file=$(mktemp)
    sed -E 's|https?://||g; s|:[0-9]*$||g; s|[/?#].*$||g' "$INPUT_FILE" | grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' > "$temp_file"

    python3 /waymore/waymore.py -i "$temp_file" -oU "$URLS_DIR/waymore.txt" -xcc
    rm "$temp_file"

    gospider -q -d 3 -S "$INPUT_FILE" -u "$RANDOM_UA" | awk '{print $3}' | grep -v 'code-200' > "$URLS_DIR/gospider.txt" &
    cat "$INPUT_FILE" | hakrawler -d 2 > "$URLS_DIR/hakrawler.txt" &
    wait
}

cat "$INPUT_FILE" | sed -E 's|https?://||g; s|:[0-9]*$||g' | cut -d '/' -f1 | sort -u | while read -r domain; do
    github-endpoints -d "$domain" -t "$GITHUB_TOKEN" >> "$GITHUB_DIR/github-endpoints.txt"
done

# 📌 Consolidar e remover duplicatas
log "📌 Removendo duplicatas de URLs..."
cat "$URLS_DIR"/*.txt | sort -u > "$URLS_DIR/unique_urls.txt"

# 📌 Esperar entre 2 e 5 segundos
sleep $((RANDOM % 4 + 2))

# 📌 Verificar URLs ativas com httpx
log "🚀 Verificando URLs ativas com httpx..."
cat "$URLS_DIR/unique_urls.txt" | httpx -mc 200,301,302,403,500 -title -tech-detect -timeout 10 -silent -o "$HTTPX_DIR/httpx_filtered.txt"

# 📌 Limpar caracteres ANSI
log "📌 Limpando saída do httpx..."
awk '{gsub(/\x1b\[[0-9;]*m/, "")}1' "$HTTPX_DIR/httpx_filtered.txt" > "$HTTPX_DIR/httpx_no_ansi.txt"

# 📌 Preparar para o dirsearch
awk '{print $1}' "$HTTPX_DIR/httpx_no_ansi.txt" | grep -E '^https?://' > "$HTTPX_DIR/httpx_clean.txt"

# 📌 Rodar dirsearch
if [ -s "$HTTPX_DIR/httpx_clean.txt" ]; then
    log "🚀 Rodando dirsearch..."
    cat "$HTTPX_DIR/httpx_clean.txt" | xargs -P 5 -I{} dirsearch -u {} -e php,html,js,zip,txt -t 50 -x 403,404 -o "$DIRSEARCH_DIR/dirsearch.txt"
else
    log "⚠ Nenhuma URL ativa encontrada. Pulando dirsearch."
fi

# 📌 Gerar relatório final
log "📊 Gerando relatório final..."
{
    echo "📌 Relatório de Execução - $(date)"
    echo "--------------------------------------------------"
    echo "🔎 Total de URLs coletadas: $(wc -l < "$URLS_DIR/unique_urls.txt")"
    echo "🚀 Total de URLs ativas: $(wc -l < "$HTTPX_DIR/httpx_clean.txt")"
    echo "📂 Resultados disponíveis em: $BASE_DIR"
} > "$REPORT_FILE"

log "✅ Finalizado! Relatório salvo em '$REPORT_FILE'."
