function Export-EscJsonReport {
<#
.SYNOPSIS
    Exports an AD CS security-assessment result set to a single JSON document.

.DESCRIPTION
    Read-only reporter. Serializes the supplied Finding collection plus an optional
    Summary object (from Get-EscPostureScore) into one self-describing JSON document:

        { schemaVersion, generatedAt, meta, summary, findings[] }

    The document is written as UTF-8 (no BOM) using ConvertTo-Json -Depth 8, which keeps
    nested Evidence objects/arrays intact. The function is fully non-destructive: it only
    reads the objects it is given and writes a report file.

    Tolerant by design:
      * If -Summary is $null, a minimal summary (counts by severity/status) is computed
        from the findings.
      * Missing fields never throw; they serialize as $null / empty collections.

.PARAMETER Finding
    Zero or more Finding [pscustomobject] items.

.PARAMETER Summary
    Optional summary object (Get-EscPostureScore shape: PostureScore, Grade, counts,
    BySeverity, TopFindings). If omitted, a minimal summary is derived from -Finding.

.PARAMETER Meta
    Optional hashtable of run metadata (Domain, Forest, GeneratedAt, Mode, Tool, etc.).
    GeneratedAt (if present) is surfaced at the top level as generatedAt.

.PARAMETER Path
    Destination file path for the JSON document.

.OUTPUTS
    [string] The path that was written.

.EXAMPLE
    Export-EscJsonReport -Finding $findings -Summary $summary -Meta @{Domain='corp.local'} -Path .\report.json
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [pscustomobject[]] $Finding,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [pscustomobject] $Summary,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable] $Meta,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    if ($null -eq $Finding) { $Finding = @() }

    $generatedAt = $null
    if ($null -ne $Meta -and $Meta.ContainsKey('GeneratedAt') -and $null -ne $Meta['GeneratedAt']) {
        $generatedAt = [string]$Meta['GeneratedAt']
    }

    $summaryObj = $Summary
    if ($null -eq $summaryObj) {
        $summaryObj = New-EscMinimalSummary -Finding $Finding
    }

    $metaObj = $null
    if ($null -ne $Meta) {
        $metaObj = [ordered]@{}
        foreach ($k in $Meta.Keys) { $metaObj[$k] = $Meta[$k] }
    }

    $orderedFindings = @($Finding | Sort-Object -Property `
        @{ Expression = { $n = 9999; if ([string]$_.Id -match 'ESC0*(\d+)') { $n = [int]$Matches[1] }; $n } }, `
        @{ Expression = { $_.RiskScore }; Descending = $true })

    $doc = [ordered]@{
        schemaVersion = '1.0'
        generatedAt   = $generatedAt
        meta          = $metaObj
        summary       = $summaryObj
        findings      = $orderedFindings
    }

    $json = $doc | ConvertTo-Json -Depth 8

    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)

    return $Path
}

function New-EscMinimalSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Finding
    )

    $sevOrder = @('Critical', 'High', 'Medium', 'Low', 'Info')
    $bySeverity = [ordered]@{}
    foreach ($s in $sevOrder) { $bySeverity[$s] = 0 }
    $byStatus = [ordered]@{}

    foreach ($f in $Finding) {
        if ($null -eq $f) { continue }

        $sev = $null
        if ($f.PSObject.Properties['Severity']) { $sev = [string]$f.Severity }
        if ([string]::IsNullOrEmpty($sev)) { $sev = 'Info' }
        if (-not $bySeverity.Contains($sev)) { $bySeverity[$sev] = 0 }
        $bySeverity[$sev] = [int]$bySeverity[$sev] + 1

        $st = $null
        if ($f.PSObject.Properties['Status']) { $st = [string]$f.Status }
        if ([string]::IsNullOrEmpty($st)) { $st = 'Unknown' }
        if (-not $byStatus.Contains($st)) { $byStatus[$st] = 0 }
        $byStatus[$st] = [int]$byStatus[$st] + 1
    }

    return [pscustomobject]@{
        PostureScore = $null
        Grade        = $null
        TotalCount   = @($Finding).Count
        BySeverity   = [pscustomobject]$bySeverity
        ByStatus     = [pscustomobject]$byStatus
        TopFindings  = @()
    }
}
