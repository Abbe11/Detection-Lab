Describe "Web attack detector" {
    It "catches the SQL injection from 203.0.113.77" {
        $result = & .\detect_webattack.ps1
        ($result | Where-Object { $_.AttackType -eq "SQL injection" }).SourceIP | Should -Be "203.0.113.77"
    }
    It "catches the path traversal" {
        $result = & .\detect_webattack.ps1
        $result | Where-Object { $_.AttackType -eq "Path traversal" } | Should -Not -BeNullOrEmpty
    }
    It "leaves the normal visits alone" {
        $result = & .\detect_webattack.ps1
        @($result).Count | Should -Be 2
    }
}
