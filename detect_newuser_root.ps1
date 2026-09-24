param(
    [string]$LogPath = ".\logs\newuser_sample.log"
)
$lines = Get-Content $LogPath
$suspicious = $lines | Select-String "new user:.*UID=0"
foreach ($hit in $suspicious) {
    $name = if ($hit.Line -match "name=(\w+)") { $matches[1] } else { "unknown" }
    [PSCustomObject]@{
        Account   = $name
        Event     = "New account created with root UID 0"
        Severity  = "CRITICAL - possible backdoor"
        Technique = "T1136 Create Account"
    }
}
