#!/bin/bash

# First part - Nuclei scan
echo "Choose input type:"
echo "1. Single URL"
echo "2. URL list file"
read -p "Enter your choice (1 or 2): " choice

if [ "$choice" = "1" ]; then
    read -p "Enter the URL: " target
    input_cmd="echo $target"
elif [ "$choice" = "2" ]; then
    read -p "Enter the path to your URL list file: " list_file
    input_cmd="cat $list_file"
else
    echo "Invalid choice"
    exit 1
fi

templates_dir="/home/x-1/coffenucleitemplates01302025"

echo "Running nuclei scans..."

# Original commands
$input_cmd | nuclei -t $templates_dir/openRedirect.yaml --retries 2 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/wp-setup-config.yaml -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/iis.yaml -c 30 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/cors.yaml -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/credentials-disclosure-all.yaml -c 30 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/blind-ssrf.yaml -c 30 -dast -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/errsqli.yaml -dast -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/cRlf.yaml -rl 50 -c 30 -o nucleiresults.txt

# Added commands for remaining templates
$input_cmd | nuclei -t $templates_dir/api_endpoints.yaml -c 30 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/cloudflare-rocketloader-htmli.yaml -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/detect-all-takeovers.yaml -c 30 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/graphql_get.yaml -c 30 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/header_blind_xss.yaml -dast -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/oob_sqli.yaml -dast -c 30 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/oob_sqli-2.yaml -dast -c 30 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/php-backup-files.yaml -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/put-method-enabled.yaml -c 30 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/response-ssrf.yaml -c 30 -dast -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/Swagger.yaml -c 30 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/x-forwarded.yaml -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/xss.yaml -dast -c 30 -o nucleiresults.txt
$input_cmd | nuclei -t $templates_dir/xxe.yaml -dast -c 30 -o nucleiresults.txt

echo "Nuclei scan complete. Starting header analysis..."

# Second part - Header analysis
declare -A EXPECTED_HEADERS=(
    ["Access-Control-Allow-Origin"]="none"
    ["Access-Control-Allow-Credentials"]="false"
    ["Access-Control-Allow-Methods"]="GET, POST"
    ["Access-Control-Allow-Headers"]="Content-Type, Authorization"
    ["Access-Control-Expose-Headers"]="Content-Length, X-Request-Id"
    ["Access-Control-Max-Age"]="86400"
    ["X-XSS-Protection"]="1; mode=block"
    ["Content-Security-Policy"]="default-src 'self'; script-src 'self' 'nonce-[random]'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'default' 'dompurify'"
    ["X-Frame-Options"]="DENY"
    ["Strict-Transport-Security"]="max-age=31536000; includeSubDomains; preload"
    ["X-Content-Type-Options"]="nosniff"
    ["Set-Cookie"]="HttpOnly; Secure; SameSite=Strict; Path=/; Domain=example.com"
    ["Referrer-Policy"]="strict-origin-when-cross-origin"
    ["Clear-Site-Data"]='"cache","cookies","storage"'
    ["Cross-Origin-Resource-Policy"]="same-origin"
    ["Cross-Origin-Embedder-Policy"]="require-corp"
    ["Cross-Origin-Opener-Policy"]="same-origin"
    ["Permissions-Policy"]="geolocation=(), microphone=(), camera=(), payment=(), usb=(), screen-wake-lock=()"
    ["Feature-Policy"]="sync-xhr 'none'; document-domain 'none'"
    ["Expect-CT"]="max-age=86400, enforce"
    ["X-Permitted-Cross-Domain-Policies"]="none"
    ["X-Download-Options"]="noopen"
    ["X-DNS-Prefetch-Control"]="off"
    ["Cache-Control"]="no-store, max-age=0"
    ["Public-Key-Pins"]="pin-sha256='base64+primary=='; pin-sha256='base64+backup=='; max-age=5184000; includeSubDomains"
    ["Timing-Allow-Origin"]="none"
    ["NEL"]='{"report_to":"default","max_age":31536000,"include_subdomains":true}'
    ["Report-To"]='{"group":"default","max_age":31536000,"endpoints":[{"url":"https://example.com/reports"}]}'
    ["Alt-Svc"]='h3=":443"; ma=86400'
    ["Sec-Fetch-Site"]="same-origin"
    ["Sec-Fetch-Mode"]="cors"
    ["Sec-Fetch-User"]="?1"
    ["Sec-Fetch-Dest"]="document"
    ["Authorization"]="Bearer [token]"
    ["WWW-Authenticate"]="Basic realm='Access'"
)

check_headers() {
    local url=$1
    local results_file="headerinforesults.txt"
    
    echo -e "\nChecking headers for: $url"
    
    headers=$(curl -sI "$url")
    if [ $? -ne 0 ]; then
        echo "Error checking $url" >&2
        return 1
    fi
    
    echo "Results for: $url" >> "$results_file"
    echo "$(printf '=%.0s' {1..100})" >> "$results_file"
    
    echo -e "\nSecurity Headers:" >> "$results_file"
    echo "$(printf '=%.0s' {1..100})" >> "$results_file"
    
    for header in "${!EXPECTED_HEADERS[@]}"; do
        value=$(echo "$headers" | grep -i "^$header:" | cut -d: -f2- | tr -d '\r' | xargs)
        if [ -n "$value" ]; then
            if [ "$value" = "${EXPECTED_HEADERS[$header]}" ]; then
                printf "%-40s Present\n" "$header" >> "$results_file"
            else
                printf "%-40s Present (Unexpected value: %s)\n" "$header" "$value" >> "$results_file"
            fi
        else
            printf "%-40s Missing\n" "$header" >> "$results_file"
        fi
    done
    
    echo -e "\nCache Headers:" >> "$results_file"
    echo "$(printf '=%.0s' {1..100})" >> "$results_file"
    
    declare -a cache_headers=("Cache-Control" "Age" "X-Cache" "ETag" "Last-Modified" "Expires" "Vary" "Pragma")
    for header in "${cache_headers[@]}"; do
        value=$(echo "$headers" | grep -i "^$header:" | cut -d: -f2- | tr -d '\r' | xargs)
        if [ -n "$value" ]; then
            printf "%-40s %s\n" "$header" "$value" >> "$results_file"
        else
            printf "%-40s Not Present\n" "$header" >> "$results_file"
        fi
    done
    
    echo -e "\nDetected Functionality:" >> "$results_file"
    echo "$(printf '=%.0s' {1..100})" >> "$results_file"
    
    if echo "$headers" | grep -qi "Accept-Ranges\|Content-Disposition: attachment"; then
        echo "[FILE] File upload/download functionality detected" >> "$results_file"
    fi
    
    if echo "$headers" | grep -qi "Content-Type: image\|video\|media"; then
        echo "[MEDIA] Media content functionality detected" >> "$results_file"
    fi
    
    if echo "$headers" | grep -qi "WWW-Authenticate\|Authorization\|Set-Cookie: .*session"; then
        echo "[AUTH] Authentication/Login functionality detected" >> "$results_file"
    fi
    
    if echo "$headers" | grep -qi "Upgrade: websocket\|Sec-WebSocket-Accept"; then
        echo "[CHAT] Chat/WebSocket functionality detected" >> "$results_file"
    fi
    
    if echo "$headers" | grep -qi "X-API-Version\|Link: .*rel="; then
        echo "[API] API endpoint detected" >> "$results_file"
    fi
    
    if echo "$headers" | grep -qi "X-Powered-By\|Server\|X-AspNet-Version"; then
        echo "[TECH] Technology stack information leaked" >> "$results_file"
    fi
    
    if echo "$headers" | grep -qi "X-Debug\|X-Runtime"; then
        echo "[DEBUG] Debug/Development information detected" >> "$results_file"
    fi
    
    if echo "$headers" | grep -qi "X-RateLimit-Limit"; then
        echo "[RATELIMIT] Rate limiting implemented" >> "$results_file"
    fi
    
    if echo "$headers" | grep -qi "X-Original-URL\|X-Forwarded-Host"; then
        echo "[PROXY] Proxy/Routing information detected" >> "$results_file"
    fi
    
    cat "$results_file"
}

process_url() {
    local url=$1
    if [[ ! $url =~ ^https?:// ]]; then
        url="http://$url"
    fi
    check_headers "$url"
}

process_url_list() {
    local file=$1
    if [ ! -f "$file" ]; then
        echo "Error: File not found - $file" >&2
        return 1
    fi
    
    while IFS= read -r url; do
        url=$(echo "$url" | tr -d '\r')
        process_url "$url"
    done < "$file"
}

compare_results() {
    echo "Comparing nuclei and header analysis results..."
    
    {
        echo "=== COMPARISON REPORT ==="
        echo "========================="
        echo
        echo "SECTION 1: AGREEMENTS"
        echo "===================="
        echo "Headers where both tools agree on findings:"
        echo
        
        nuclei_findings=$(grep -i "header" nucleiresults.txt || true)
        header_findings=$(grep -i "Present\|Missing" headerinforesults.txt || true)
        
        while IFS= read -r line; do
            header_name=$(echo "$line" | grep -o '[A-Za-z-]*-[A-Za-z-]*' | head -1)
            if [ -n "$header_name" ]; then
                if grep -qi "$header_name" headerinforesults.txt; then
                    nuclei_value=$(echo "$line" | grep -o '[^:]*$')
                    header_value=$(grep -i "$header_name" headerinforesults.txt | grep -o '[^:]*$')
                    if [ "$nuclei_value" = "$header_value" ]; then
                        echo "✓ $header_name: Both tools agree"
                        echo "  Value: $nuclei_value"
                        echo
                    fi
                fi
            fi
        done <<< "$nuclei_findings"
        
        echo
        echo "SECTION 2: DISAGREEMENTS"
        echo "======================="
        echo "Headers where tools found different results:"
        echo
        
        while IFS= read -r line; do
            header_name=$(echo "$line" | grep -o '[A-Za-z-]*-[A-Za-z-]*' | head -1)
            if [ -n "$header_name" ]; then
                if grep -qi "$header_name" headerinforesults.txt; then
                    nuclei_value=$(echo "$line" | grep -o '[^:]*$')
                    header_value=$(grep -i "$header_name" headerinforesults.txt | grep -o '[^:]*$')
                    if [ "$nuclei_value" != "$header_value" ]; then
                        echo "! $header_name: Tools disagree"
                        echo "  Nuclei found: $nuclei_value"
                        echo "  Header scanner found: $header_value"
                        echo
                    fi
                fi
            fi
        done <<< "$nuclei_findings"
        
        echo
        echo "SECTION 3: UNIQUE FINDINGS"
        echo "========================="
        echo "Headers found by only one tool:"
        echo
        
        echo "Nuclei only:"
        while IFS= read -r line; do
            header_name=$(echo "$line" | grep -o '[A-Za-z-]*-[A-Za-z-]*' | head -1)
            if [ -n "$header_name" ]; then
                if ! grep -qi "$header_name" headerinforesults.txt; then
                    echo "  $header_name: $line"
                fi
            fi
        done <<< "$nuclei_findings"
        
        echo
        echo "Header scanner only:"
        while IFS= read -r line; do
            header_name=$(echo "$line" | grep -o '[A-Za-z-]*-[A-Za-z-]*' | head -1)
            if [ -n "$header_name" ]; then
                if ! grep -qi "$header_name" nucleiresults.txt; then
                    echo "  $header_name: $line"
                fi
            fi
        done <<< "$header_findings"
        
    } > comparison_report.txt
    
    echo "Comparison complete! Results saved in comparison_report.txt"
}

case $choice in
    1)
        url=$target
        process_url "$url"
        ;;
    2)
        process_url_list "$list_file"
        ;;
esac

compare_results

echo "All scans and comparisons complete!"
echo "- Nuclei results: nucleiresults.txt"
echo "- Header analysis: headerinforesults.txt"
echo "- Comparison report: comparison_report.txt"

