param(
    [string]$LogPath = ".\logs\web_access_sample.log"
)

$lines = Get-Content $LogPath

# Patterns that show up in web attacks (SQL injection or path traversal)
$attackPattern = "(' OR |UNION SELECT|\.\./|/etc/passwd)"

$hits = $lines | Select-String $attackPattern

foreach ($hit in $hits) {
    $ip   = if ($hit.Line -match "^(\d{1,3}(\.\d{1,3}){3})") { $matches[1] } else { "unknown" }
    $kind = if ($hit.Line -match "\.\./|/etc/passwd") { "Path traversal" } else { "SQL injection" }
    [PSCustomObject]@{
        SourceIP   = $ip
        AttackType = $kind
        Severity   = "High - web attack attempt"
        Technique  = "T1190 Exploit Public-Facing Application"
    }
}
