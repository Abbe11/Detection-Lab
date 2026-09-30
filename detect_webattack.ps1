param(
    [string]$LogPath = ".\logs\web_access_sample.log"
)

$lines = Get-Content $LogPath

# SQL injection or path traversal patterns
$attackPattern = "(' OR |UNION SELECT|\.\./|/etc/passwd)"

foreach ($line in $lines) {
    # Decode URL-encoding first, so %27%20OR becomes '"'"' OR and cannot hide
    $decoded = [System.Uri]::UnescapeDataString($line)

    if ($decoded -match $attackPattern) {
        # Grab the first IPv4 anywhere in the line, so ::ffff: prefixes do not break it
        $ip = if ($line -match "(\d{1,3}(\.\d{1,3}){3})") { $matches[1] } else { "unknown" }
        $kind = if ($decoded -match "\.\./|/etc/passwd") { "Path traversal" } else { "SQL injection" }
        [PSCustomObject]@{
            SourceIP   = $ip
            AttackType = $kind
            Severity   = "High - web attack attempt"
            Technique  = "T1190 Exploit Public-Facing Application"
        }
    }
}
