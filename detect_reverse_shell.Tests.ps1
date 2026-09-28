Describe "Reverse shell and miner detector" {
    It "flags the reverse shell spawned by nginx" {
        $result = & .\detect_reverse_shell.ps1
        ($result | Where-Object { $_.AttackType -like "Reverse shell*" }) | Should -Not -BeNullOrEmpty
    }
    It "flags the crypto miner" {
        $result = & .\detect_reverse_shell.ps1
        ($result | Where-Object { $_.AttackType -like "Crypto miner*" }) | Should -Not -BeNullOrEmpty
    }
    It "leaves normal processes alone (php-fpm, backup.sh)" {
        $result = & .\detect_reverse_shell.ps1
        @($result).Count | Should -Be 2
    }
}
