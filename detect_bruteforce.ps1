param(
    [string]$LogPath = ".\logs\sample_auth.log",
    [int]$Threshold = 5
)

$lines = Get-Content $LogPath

$noisyIps = $lines |
    Select-String 'Failed password.*from (\d{1,3}(\.\d{1,3}){3})' |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Group-Object |
    Where-Object { $_.Count -ge $Threshold }

$successIps = $lines |
    Select-String 'Accepted password.*from (\d{1,3}(\.\d{1,3}){3})' |
    ForEach-Object { $_.Matches.Groups[1].Value }

foreach ($ip in $noisyIps) {
    $compromised = $successIps -contains $ip.Name
    [PSCustomObject]@{
        SourceIP    = $ip.Name
        FailedCount = $ip.Count
        Succeeded   = $compromised
        Severity    = if ($compromised) { "CRITICAL - likely compromise" } else { "High - brute-force attempt" }
        Technique   = "T1110 Brute Force"
    }
}
