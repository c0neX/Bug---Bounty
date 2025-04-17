#!/bin/bash

# OpenBash Pentesting Tools - Stealthy and Efficient Offensive Crawler
# Author: OpenBash Security Team

set -e

INPUT="$1"
OUTDIR="output_$(date +%s)"
THREADS=5
DELAY_MIN=1
DELAY_MAX=5
UA_LIST=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
  "Mozilla/5.0 (X11; Linux x86_64)"
  "Googlebot/2.1 (+http://www.google.com/bot.html)"
  "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
)

mkdir -p "$OUTDIR"

echo "[+] Starting stealthy crawler..."
echo "[+] Results in: $OUTDIR"

# 1. Prepare targets
if [[ -f "$INPUT" ]]; then
  cat "$INPUT" | sort -u > "$OUTDIR/targets.txt"
else
  echo "$INPUT" > "$OUTDIR/targets.txt"
fi

# 2. Random delay function
random_sleep() {
  delay=$(shuf -i $DELAY_MIN-$DELAY_MAX -n 1)
  sleep "$delay"
}

# 3. Stealthy crawling function with custom headers
stealth_crawl() {
  TARGET="$1"
  UA="${UA_LIST[$RANDOM % ${#UA_LIST[@]}]}"

  echo "[*] Stealth crawling: $TARGET with User-Agent: $UA"

  # Katana with real headers and request control
  katana -u "$TARGET" \
      -d 2 \
      -timeout 10 \
      -rate-limit 150 \
      -silent \
      -no-color \
      -js \
      -kf all \
      -H "User-Agent: $UA" \
      -H "Accept: text/html,application/xhtml+xml" \
      -H "Accept-Language: en-US,en;q=0.5" \
      -H "Connection: keep-alive"

  random_sleep
}

# 4. Active crawling in parallel with control
echo "[*] Executing crawling with stealth controls..."

> "$OUTDIR/katana_raw.txt"

cat "$OUTDIR/targets.txt" | while read target; do
  (
    stealth_crawl "$target"
  ) >> "$OUTDIR/katana_raw.txt" &

  # Limit number of parallel processes
  while [[ $(jobs | wc -l) -ge $THREADS ]]; do
    sleep 0.5
  done
done

wait

# 5. Archived URLs from OSINT sources (GAU)
echo "[*] Collecting archived URLs with gau (stealth mode)..."
cat "$OUTDIR/targets.txt" | gau --subs --blacklist wayback,otx > "$OUTDIR/gau_raw.txt"

# 6. Consolidate URLs
echo "[*] Consolidating all URLs..."
cat "$OUTDIR/katana_raw.txt" "$OUTDIR/gau_raw.txt" | sort -u > "$OUTDIR/all_urls.txt"

# 7. Detect parameters
grep '?' "$OUTDIR/all_urls.txt" | grep '=' > "$OUTDIR/urls_with_params.txt"
cat "$OUTDIR/urls_with_params.txt" | sed -E 's/.*\?(.*)/\1/' | tr '&' '\n' | cut -d '=' -f1 | sort -u > "$OUTDIR/param_names.txt"

# 8. Detect interesting endpoints
egrep '\.php|\.asp|\.aspx|\.jsp|\.json|\.js|\.xml|\.txt|\.cgi|\.pl' "$OUTDIR/all_urls.txt" > "$OUTDIR/interesting_endpoints.txt"

# 9. Results
echo "[+] Phase finished successfully."
echo "    URLs collected: $(wc -l < "$OUTDIR/all_urls.txt")"
echo "    URLs with parameters: $(wc -l < "$OUTDIR/urls_with_params.txt")"
echo "    Unique parameters: $(wc -l < "$OUTDIR/param_names.txt")"
echo "    Interesting endpoints: $(wc -l < "$OUTDIR/interesting_endpoints.txt")"
