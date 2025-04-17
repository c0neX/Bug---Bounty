#!/bin/bash

###########################
# MAIN CONFIGURATION
###########################

TEMP_DIR="tmp"
OUTPUT_DIR="output_scan"
RESOLVERS="resolvers.txt"
RATE_LIMIT=150

USER_AGENTS=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
  "Mozilla/5.0 (X11; Linux x86_64; rv:92.0)"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X)"
  "Mozilla/5.0 (Linux; Android 10; SM-G975F)"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/***.0.0.0 Safari/***.**"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:***.0) Gecko/20100101 Firefox/***.*"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/***.0.0.0 Safari/***.**"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:***.0) Gecko/20100101 Firefox/***.*"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/***.0.0.0 Safari/***.**"
  "Mozilla/5.0 (X11; Linux x86_64; rv:***.0) Gecko/20100101 Firefox/***.*"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/***.*.***.**"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/***** Safari/****.**"
)

mkdir -p "$TEMP_DIR" "$OUTPUT_DIR"

if [ -z "$1" ]; then
  echo "Usage: $0 <domain> or $0 -l <file_with_domains>"
  exit 1
fi

if [ "$1" != "-l" ]; then
  DOMAINS=("$1")
else
  if [ ! -f "$2" ]; then
    echo "File $2 not found!"
    exit 1
  fi
  mapfile -t DOMAINS < "$2"
fi

echo "[*] Starting recon..."

for DOMAIN in "${DOMAINS[@]}"; do
  START_TIME=$(date +%s)
  DOMAIN_ID=$(echo "$DOMAIN" | tr -dc '[:alnum:]._-')

  echo -e "\n[*] Processing $DOMAIN"
  rm -f "$TEMP_DIR/"*_"$DOMAIN_ID"

  ###########################
  # PASSIVE ENUMERATION
  ###########################

  echo "[*] Enumerating subdomains with passive tools..."
  subfinder -d "$DOMAIN" -silent -o "$TEMP_DIR/subfinder_$DOMAIN_ID" &
  amass enum -passive -d "$DOMAIN" -silent -o "$TEMP_DIR/amass_$DOMAIN_ID" &
  assetfinder --subs-only "$DOMAIN" > "$TEMP_DIR/assetfinder_$DOMAIN_ID" &
  curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" |
    jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > "$TEMP_DIR/crtsh_$DOMAIN_ID" &
  wait

  cat "$TEMP_DIR/"*"$DOMAIN_ID" | sort -u > "$TEMP_DIR/all_subs_$DOMAIN_ID.txt"
  TOTAL_FOUND=$(wc -l < "$TEMP_DIR/all_subs_$DOMAIN_ID.txt")
  echo "[+] $TOTAL_FOUND unique subdomains found."

  if [[ "$TOTAL_FOUND" -eq 0 ]]; then
    notify -silent -title "Recon finished" -msg "🚨 No subdomains found for $DOMAIN"
    continue
  fi

  ###########################
  # DNS RESOLUTION
  ###########################

  echo "[*] Resolving subdomains with shuffledns..."
  shuffledns -silent \
    -list "$TEMP_DIR/all_subs_$DOMAIN_ID.txt" \
    -r "$RESOLVERS" \
    -mode resolve \
    -o "$OUTPUT_DIR/resolved_hosts_$DOMAIN_ID.txt" || touch "$OUTPUT_DIR/resolved_hosts_$DOMAIN_ID.txt"

  RESOLVED_COUNT=$(wc -l < "$OUTPUT_DIR/resolved_hosts_$DOMAIN_ID.txt")
  echo "[+] $RESOLVED_COUNT subdomains responded via DNS."

  ###########################
  # HTTP DETECTION
  ###########################

  RANDOM_INDEX=$((RANDOM % ${#USER_AGENTS[@]}))
  RANDOM_UA="${USER_AGENTS[$RANDOM_INDEX]}"

  echo "[*] Scanning HTTP ports with httpx (User-Agent: $RANDOM_UA)..."
  cat "$OUTPUT_DIR/resolved_hosts_$DOMAIN_ID.txt" | httpx -silent -no-color \
    -H "User-Agent: $RANDOM_UA" \
    -rate-limit "$RATE_LIMIT" \
    -p 80,443,8080,8443 \
    -threads 50 > "$OUTPUT_DIR/http_active_$DOMAIN_ID.txt"

  ACTIVE_COUNT=$(wc -l < "$OUTPUT_DIR/http_active_$DOMAIN_ID.txt")

  END_TIME=$(date +%s)
  DURATION=$((END_TIME - START_TIME))

  ###########################
  # LOG/NOTIFICATION (with notify)
  ###########################

  echo "[✓] Recon of $DOMAIN finished in ${DURATION}s"
  echo "    → Unique subdomains: $TOTAL_FOUND"
  echo "    → Valid DNS: $RESOLVED_COUNT"
  echo "    → Active HTTP services: $ACTIVE_COUNT"

  notify -silent -title "Recon finished" -msg "✅ Recon Finished for $DOMAIN in ${DURATION}s
  → Unique Subdomains: $TOTAL_FOUND
  → Resolved DNS: $RESOLVED_COUNT
  → Active HTTP: $ACTIVE_COUNT"

done

echo "[✅] All domains were processed successfully."
