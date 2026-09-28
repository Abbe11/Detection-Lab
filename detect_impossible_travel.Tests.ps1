Describe "Impossible travel detector" {
    It "flags alice (Kenya to Russia in 19 minutes)" {
        $result = & .\detect_impossible_travel.ps1
        ($result | Where-Object { $_.User -eq "alice" }) | Should -Not -BeNullOrEmpty
    }
    It "does not flag carol (16 hours is enough time to fly)" {
        $result = & .\detect_impossible_travel.ps1
        ($result | Where-Object { $_.User -eq "carol" }) | Should -BeNullOrEmpty
    }
    It "does not flag bob (never left Kenya)" {
        $result = & .\detect_impossible_travel.ps1
        ($result | Where-Object { $_.User -eq "bob" }) | Should -BeNullOrEmpty
    }
}
