param(
    [string]$LogPath = ".\logs\signin_sample.csv",
    [int]$MinHours = 6
)

$logins = Import-Csv $LogPath | Where-Object { $_.result -eq "Success" }

foreach ($group in ($logins | Group-Object user)) {
    $sorted = $group.Group | Sort-Object { [datetime]$_.time }
    for ($i = 1; $i -lt $sorted.Count; $i++) {
        $prev = $sorted[$i - 1]
        $curr = $sorted[$i]
        if ($prev.country -ne $curr.country) {
            $gap = ([datetime]$curr.time - [datetime]$prev.time).TotalHours
            if ($gap -lt $MinHours) {
                [PSCustomObject]@{
                    User      = $curr.user
                    From      = "$($prev.country) at $($prev.time)"
                    To        = "$($curr.country) at $($curr.time)"
                    GapHours  = [math]::Round($gap, 2)
                    Severity  = "High - impossible travel"
                    Technique = "T1078 Valid Accounts"
                }
            }
        }
    }
}
