param(
    [string]$LogPath = ".\logs\process_sample.csv"
)

$events = Import-Csv $LogPath

# Web/service processes that should never launch a shell or a miner
$webParents = "nginx|apache|apache2|httpd|php-fpm"
# Things a web server has no honest reason to start
$badChild   = "bash|/bin/sh|(^| )sh|ncat|nc |python.*-c|/dev/tcp|xmrig"

foreach ($e in $events) {
    $shellFromWeb = ($e.parent_process -match $webParents) -and ($e.child_process -match $badChild)
    $miner        = $e.child_process -match "xmrig"
    if ($shellFromWeb -or $miner) {
        $type = if ($e.child_process -match "xmrig") { "Crypto miner (T1496)" } else { "Reverse shell (T1059)" }
        [PSCustomObject]@{
            Host       = $e.host
            Parent     = $e.parent_process
            Child      = $e.child_process
            DestIP     = $e.dest_ip
            AttackType = $type
            Severity   = "Critical - post-exploitation"
        }
    }
}
