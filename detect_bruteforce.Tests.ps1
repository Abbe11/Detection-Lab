Describe "SSH brute-force detector" {
    It "flags attacker 203.0.113.45 as a compromise" {
        $result = & .\detect_bruteforce.ps1
        $alert  = $result | Where-Object { $_.SourceIP -eq "203.0.113.45" }
        $alert            | Should -Not -BeNullOrEmpty
        $alert.Succeeded  | Should -Be $true
    }
}
