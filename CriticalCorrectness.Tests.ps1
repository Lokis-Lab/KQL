Describe 'KQL critical correctness guards' {
  BeforeAll {
    $repoRoot = $PSScriptRoot
    $script:Files = @{
      Tier0 = Join-Path $repoRoot 'Auth-Logons-Identity/AD_Sensitive_Group_Modifications.kql'
      AsrSummary = Join-Path $repoRoot 'ASR/ASR_BlockedEvents_Summary_7d.kql'
      HealthMatrix = Join-Path $repoRoot 'Defender-Health-Reports/Defender_Endpoint_Configuration_Health_Matrix.kql'
      SccmJoin = Join-Path $repoRoot 'SCCM-Integration/SCCM_Process_Execution_and_Security_Alert_Join.kql'
    }
  }

  It 'keeps Tier0 datatable rows comma-separated' {
    $content = Get-Content -LiteralPath $script:Files.Tier0 -Raw
    $content | Should -Match "'Domain Controllers',\s*\r?\n'Administrators',"
  }

  It 'filters enforced ASR events with numeric IsAudit' {
    $content = Get-Content -LiteralPath $script:Files.AsrSummary -Raw
    $content | Should -Match 'Parsed\.IsAudit == 0'
    $content | Should -Not -Match 'Parsed\.IsAudit == "false"'
  }

  It 'deduplicates secure configuration assessments before pivoting' {
    $content = Get-Content -LiteralPath $script:Files.HealthMatrix -Raw
    $content | Should -Match 'arg_max\(Timestamp, \*\) by DeviceId, ConfigurationId'
  }

  It 'bounds SCCM process correlation to the last 30 days' {
    $content = Get-Content -LiteralPath $script:Files.SccmJoin -Raw
    $part2 = ($content -split '// Part 2')[1]
    $part2 | Should -Match 'Timestamp > ago\(30d\)'
  }
}
