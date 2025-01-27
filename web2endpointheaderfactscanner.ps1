# Expected header values for mitigations
$EXPECTED_HEADERS = @{
    # Original Headers
    "Access-Control-Allow-Origin" = "none"
    "Access-Control-Allow-Credentials" = "false"
    "Access-Control-Allow-Methods" = "GET, POST"
    "Access-Control-Allow-Headers" = "Content-Type, Authorization"
    "Access-Control-Expose-Headers" = "Content-Length, X-Request-Id"
    "Access-Control-Max-Age" = "86400"
    "X-XSS-Protection" = "1; mode=block"
    "Content-Security-Policy" = "default-src 'self'; script-src 'self' 'nonce-[random]'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'default' 'dompurify'"
    "X-Frame-Options" = "DENY"
    "Strict-Transport-Security" = "max-age=31536000; includeSubDomains; preload"
    "X-Content-Type-Options" = "nosniff"
    "Set-Cookie" = "HttpOnly; Secure; SameSite=Strict; Path=/; Domain=example.com"
    "Referrer-Policy" = "strict-origin-when-cross-origin"
    "Clear-Site-Data" = "`"cache`",`"cookies`",`"storage`""
    "Cross-Origin-Resource-Policy" = "same-origin"
    "Cross-Origin-Embedder-Policy" = "require-corp"
    "Cross-Origin-Opener-Policy" = "same-origin"
    "Permissions-Policy" = "geolocation=(), microphone=(), camera=(), payment=(), usb=(), screen-wake-lock=()"
    "Feature-Policy" = "sync-xhr 'none'; document-domain 'none'"
    "Expect-CT" = "max-age=86400, enforce"
    "X-Permitted-Cross-Domain-Policies" = "none"
    "X-Download-Options" = "noopen"
    "X-DNS-Prefetch-Control" = "off"
    "Cache-Control" = "no-store, max-age=0"
    "Public-Key-Pins" = "pin-sha256='base64+primary=='; pin-sha256='base64+backup=='; max-age=5184000; includeSubDomains"
    "Timing-Allow-Origin" = "none"

    # New 2025 Security Headers
    "NEL" = '{"report_to":"default","max_age":31536000,"include_subdomains":true}'
    "Report-To" = '{"group":"default","max_age":31536000,"endpoints":[{"url":"https://example.com/reports"}]}'
    "Alt-Svc" = 'h3=":443"; ma=86400'
    "Sec-Fetch-Site" = "same-origin"
    "Sec-Fetch-Mode" = "cors"
    "Sec-Fetch-User" = "?1"
    "Sec-Fetch-Dest" = "document"
    "Authorization" = "Bearer [token]"
    "WWW-Authenticate" = "Basic realm='Access'"
}

function Check-Headers {
    param (
        [string]$url
    )
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing
        $results = @{}
        
        # Check standard security headers
        foreach ($header in $EXPECTED_HEADERS.Keys) {
            $headerPresent = $response.Headers[$header] -eq $EXPECTED_HEADERS[$header]
            $results[$header] = $headerPresent
        }
        
        # Add cache header checks
        $results["Cache-Headers"] = @{
            "Cache-Control" = $response.Headers["Cache-Control"]
            "Age" = $response.Headers["Age"]
            "X-Cache" = $response.Headers["X-Cache"]
            "ETag" = $response.Headers["ETag"]
            "Last-Modified" = $response.Headers["Last-Modified"]
            "Expires" = $response.Headers["Expires"]
            "Vary" = $response.Headers["Vary"]
            "Pragma" = $response.Headers["Pragma"]
        }

        # Add functionality detection
        $results["Functionality-Headers"] = @{
            # File Upload/Download Indicators
            "Accept-Ranges" = $response.Headers["Accept-Ranges"]
            "Content-Disposition" = $response.Headers["Content-Disposition"]
            "Content-Type" = $response.Headers["Content-Type"]
            
            # Media/Image Indicators
            "Content-Length" = $response.Headers["Content-Length"]
            "X-Content-Type-Options" = $response.Headers["X-Content-Type-Options"]
            "Accept" = $response.Headers["Accept"]
            
            # Authentication/Login Indicators
            "WWW-Authenticate" = $response.Headers["WWW-Authenticate"]
            "Authorization" = $response.Headers["Authorization"]
            "Set-Cookie" = $response.Headers["Set-Cookie"]
            
            # WebSocket/Chat Indicators
            "Upgrade" = $response.Headers["Upgrade"]
            "Connection" = $response.Headers["Connection"]
            "Sec-WebSocket-Accept" = $response.Headers["Sec-WebSocket-Accept"]

            # API and Technology Stack Indicators
            "X-API-Version" = $response.Headers["X-API-Version"]
            "X-Powered-By" = $response.Headers["X-Powered-By"]
            "Server" = $response.Headers["Server"]
            "X-AspNet-Version" = $response.Headers["X-AspNet-Version"]
            "X-Runtime" = $response.Headers["X-Runtime"]
            "X-Generator" = $response.Headers["X-Generator"]
            "X-Debug" = $response.Headers["X-Debug"]
            "X-Backend-Server" = $response.Headers["X-Backend-Server"]
            "X-RateLimit-Limit" = $response.Headers["X-RateLimit-Limit"]
            "Location" = $response.Headers["Location"]
            "Link" = $response.Headers["Link"]
            "X-Original-URL" = $response.Headers["X-Original-URL"]
            "X-Forwarded-Host" = $response.Headers["X-Forwarded-Host"]
        }

        # Add functionality analysis
        $results["Detected-Features"] = @{
            "File-Operations" = $false
            "Media-Content" = $false
            "Authentication" = $false
            "Chat-Features" = $false
            "API-Features" = $false
            "Tech-Stack" = $false
            "Debug-Info" = $false
            "Rate-Limiting" = $false
            "Proxy-Info" = $false
            "Details" = @()
        }

        # Analyze headers for functionality
        if ($response.Headers["Accept-Ranges"] -or 
            $response.Headers["Content-Disposition"] -match "attachment") {
            $results["Detected-Features"]["File-Operations"] = $true
            $results["Detected-Features"]["Details"] += "[FILE] File upload/download functionality detected"
        }

        if ($response.Headers["Content-Type"] -match "image|video|media" -or 
            $response.Headers["Accept"] -match "image|video|media") {
            $results["Detected-Features"]["Media-Content"] = $true
            $results["Detected-Features"]["Details"] += "[MEDIA] Media content functionality detected"
        }

        if ($response.Headers["WWW-Authenticate"] -or 
            $response.Headers["Authorization"] -or 
            $response.Headers["Set-Cookie"] -match "session|auth|login") {
            $results["Detected-Features"]["Authentication"] = $true
            $results["Detected-Features"]["Details"] += "[AUTH] Authentication/Login functionality detected"
        }

        if ($response.Headers["Upgrade"] -match "websocket" -or 
            $response.Headers["Sec-WebSocket-Accept"]) {
            $results["Detected-Features"]["Chat-Features"] = $true
            $results["Detected-Features"]["Details"] += "[CHAT] Chat/WebSocket functionality detected"
        }

        if ($response.Headers["X-API-Version"] -or 
            $response.Headers["Link"] -match "rel=") {
            $results["Detected-Features"]["API-Features"] = $true
            $results["Detected-Features"]["Details"] += "[API] API endpoint detected"
        }

        if ($response.Headers["X-Powered-By"] -or 
            $response.Headers["Server"] -or
            $response.Headers["X-AspNet-Version"]) {
            $results["Detected-Features"]["Tech-Stack"] = $true
            $results["Detected-Features"]["Details"] += "[TECH] Technology stack information leaked"
        }

        if ($response.Headers["X-Debug"] -or 
            $response.Headers["X-Runtime"]) {
            $results["Detected-Features"]["Debug-Info"] = $true
            $results["Detected-Features"]["Details"] += "[DEBUG] Debug/Development information detected"
        }

        if ($response.Headers["X-RateLimit-Limit"]) {
            $results["Detected-Features"]["Rate-Limiting"] = $true
            $results["Detected-Features"]["Details"] += "[RATELIMIT] Rate limiting implemented"
        }

        if ($response.Headers["X-Original-URL"] -or 
            $response.Headers["X-Forwarded-Host"]) {
            $results["Detected-Features"]["Proxy-Info"] = $true
            $results["Detected-Features"]["Details"] += "[PROXY] Proxy/Routing information detected"
        }
        
        return $results
    }
    catch {
        Write-Host "Error checking $url : $_" -ForegroundColor Red
        return $null
    }
}

function Process-Url {
    param (
        [string]$url
    )
    
    Write-Host "`nChecking headers for: $url" -ForegroundColor Cyan
    $results = Check-Headers -url $url
    
    if ($results) {
        # Console output
        Write-Host "`nResults for: $url"
        Write-Host ("=" * 100)
        
        # Standard security headers
        Write-Host "`nSecurity Headers:" -ForegroundColor Yellow
        foreach ($header in $results.Keys | Where-Object { $_ -ne "Cache-Headers" -and $_ -ne "Functionality-Headers" -and $_ -ne "Detected-Features" }) {
            $status = if ($results[$header]) { "Present" } else { "Missing" }
            Write-Host ("{0,-40} {1}" -f $header, $status)
        }
        
        # Cache headers section
        Write-Host "`nCache Headers:" -ForegroundColor Yellow
        Write-Host ("=" * 100)
        foreach ($cacheHeader in $results["Cache-Headers"].Keys) {
            $value = if ($results["Cache-Headers"][$cacheHeader]) { $results["Cache-Headers"][$cacheHeader] } else { "Not Present" }
            Write-Host ("{0,-40} {1}" -f $cacheHeader, $value)
        }

        # Functionality Detection section
        Write-Host "`nDetected Functionality:" -ForegroundColor Green
        Write-Host ("=" * 100)
        if ($results["Detected-Features"]["Details"].Count -gt 0) {
            foreach ($detail in $results["Detected-Features"]["Details"]) {
                Write-Host $detail
            }
        } else {
            Write-Host "No special functionality detected in headers"
        }

        # Save to file
        "Results for: $url" | Out-File -FilePath "headerinforesults.txt" -Append
        "=" * 100 | Out-File -FilePath "headerinforesults.txt" -Append
        
        # Save security headers
        "`nSecurity Headers:" | Out-File -FilePath "headerinforesults.txt" -Append
        "=" * 100 | Out-File -FilePath "headerinforesults.txt" -Append
        foreach ($header in $results.Keys | Where-Object { $_ -ne "Cache-Headers" -and $_ -ne "Functionality-Headers" -and $_ -ne "Detected-Features" }) {
            $status = if ($results[$header]) { "Present" } else { "Missing" }
            "{0,-40} {1}" -f $header, $status | Out-File -FilePath "headerinforesults.txt" -Append
        }
        
        # Save cache headers
        "`nCache Headers:" | Out-File -FilePath "headerinforesults.txt" -Append
        "=" * 100 | Out-File -FilePath "headerinforesults.txt" -Append
        foreach ($cacheHeader in $results["Cache-Headers"].Keys) {
            $value = if ($results["Cache-Headers"][$cacheHeader]) { $results["Cache-Headers"][$cacheHeader] } else { "Not Present" }
            "{0,-40} {1}" -f $cacheHeader, $value | Out-File -FilePath "headerinforesults.txt" -Append
        }

        # Save functionality details
        "`nDetected Functionality:" | Out-File -FilePath "headerinforesults.txt" -Append
        "=" * 100 | Out-File -FilePath "headerinforesults.txt" -Append
        if ($results["Detected-Features"]["Details"].Count -gt 0) {
            $results["Detected-Features"]["Details"] | Out-File -FilePath "headerinforesults.txt" -Append
        } else {
            "No special functionality detected in headers" | Out-File -FilePath "headerinforesults.txt" -Append
        }
        "`n" | Out-File -FilePath "headerinforesults.txt" -Append
    }
}

function Process-UrlList {
    param (
        [string]$filePath
    )
    
    if (-not (Test-Path $filePath)) {
        Write-Host "Error: File not found - $filePath" -ForegroundColor Red
        return
    }
    
    $urls = Get-Content $filePath
    foreach ($url in $urls) {
        $url = $url.Trim()
        if (-not $url.StartsWith("http")) {
            $url = "http://" + $url
        }
        Process-Url -url $url
    }
}

# Main menu
Write-Host "Select an option to run the script:" -ForegroundColor Yellow
Write-Host "1. Check a single URL"
Write-Host "2. Check a single IP address"
Write-Host "3. Check a list of URLs in urls.txt"

$choice = Read-Host "`nEnter your choice (1/2/3)"

switch ($choice) {
    "1" {
        $url = Read-Host "Enter the URL to check"
        if (-not $url.StartsWith("http")) {
            $url = "http://" + $url
        }
        Process-Url -url $url
    }
    "2" {
        $ip = Read-Host "Enter the IP address to check"
        $url = "http://" + $ip
        Process-Url -url $url
    }
    "3" {
        $filePath = Read-Host "Enter the path to the URL list file (default: urls.txt)"
        if (-not $filePath) {
            $filePath = "urls.txt"
        }
        Process-UrlList -filePath $filePath
    }
    default {
        Write-Host "Invalid choice. Please run the script again and select 1, 2, or 3." -ForegroundColor Red
    }
}
