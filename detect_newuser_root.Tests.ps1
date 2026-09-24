Describe "New root-account detector" {
    It "flags the backdoor account support (UID 0)" {
        $result = & .\detect_newuser_root.ps1
        $alert  = $result | Where-Object { $_.Account -eq "support" }
        $alert           | Should -Not -BeNullOrEmpty
        $alert.Severity  | Should -Match "CRITICAL"
    }
}
