#!/bin/bash

# Verifica se o usuário passou argumentos suficientes
if [ -z "$1" ]; then
    echo "Uso: $0 <domínio> ou $0 -l <arquivo_com_domínios>"
    exit 1
fi

# Variáveis
TEMP_DIR="tmp"
OUTPUT_DIR="output_scan"
WORDLIST="subdomains-top1million-110000.txt"
RESOLVERS="resolvers.txt"

# Criar diretórios necessários
mkdir -p "$TEMP_DIR" "$OUTPUT_DIR"

LOG_FILE="$OUTPUT_DIR/scan.log"
exec > >(tee -a "$LOG_FILE") 2>&1  

# Se for passado um único domínio
if [ "$1" != "-l" ]; then
    DOMAINS=("$1")
else
    # Se for passado um arquivo com domínios, garantir que ele exista
    if [ ! -f "$2" ]; then
        echo "Arquivo $2 não encontrado!"
        exit 1
    fi
    mapfile -t DOMAINS < "$2"  # Lê os domínios do arquivo corretamente
fi

echo "[*] Iniciando enumeração de subdomínios..."

# Processa um domínio por vez
for DOMAIN in "${DOMAINS[@]}"; do
    echo "[*] Processando domínio: $DOMAIN"

    # Remover arquivos antigos para evitar lixo de domínios anteriores
    rm -f "$TEMP_DIR/subfinder_$DOMAIN" "$TEMP_DIR/amass_$DOMAIN" "$TEMP_DIR/all_hosts"

    # Executar Subfinder e Amass sequencialmente
    echo "[*] Rodando Subfinder..."
    subfinder -d "$DOMAIN" -o "$TEMP_DIR/subfinder_$DOMAIN"

    echo "[*] Rodando Amass..."
    amass enum -passive -d "$DOMAIN" -o "$TEMP_DIR/amass_$DOMAIN"

    # Consolidar subdomínios encontrados
    cat "$TEMP_DIR/subfinder_$DOMAIN" "$TEMP_DIR/amass_$DOMAIN" | sort -u > "$TEMP_DIR/all_hosts"

    # Se não houver subdomínios, pula para o próximo domínio
    if [[ ! -s "$TEMP_DIR/all_hosts" ]]; then
        echo "[!] Nenhum subdomínio encontrado para $DOMAIN. Pulando para o próximo."
        continue
    fi

    # Resolução DNS
    echo "[*] Executando resolução DNS com shuffledns..."
    shuffledns -silent -list "$TEMP_DIR/all_hosts" -r "$RESOLVERS" -mode resolve -o "$OUTPUT_DIR/resolved_hosts_$DOMAIN.txt" || touch "$OUTPUT_DIR/resolved_hosts_$DOMAIN.txt"

    # Teste de subdomínios ativos
    echo "[*] Testando subdomínios ativos com HTTPX..."
    cat "$OUTPUT_DIR/resolved_hosts_$DOMAIN.txt" | httpx -silent -p 80,443,8080,8443 -threads 100 > "$OUTPUT_DIR/http200_$DOMAIN.txt"

    echo "[+] Recon para $DOMAIN concluído!"
    echo "[+] Resultados salvos em $OUTPUT_DIR/resolved_hosts_$DOMAIN.txt e $OUTPUT_DIR/http200_$DOMAIN.txt"
done

echo "[✅] Todos os domínios foram processados com sucesso!"
