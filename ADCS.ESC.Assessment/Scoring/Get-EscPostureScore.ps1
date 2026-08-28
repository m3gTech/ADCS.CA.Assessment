function Get-EscPostureScore {
    <#
    .SYNOPSIS
        Aggregates scored ESC Findings into an overall Posture Score (0-100) summary.
    .DESCRIPTION
        Implements the authoritative Posture Score model:

            StatusWeight : Vulnerable=1.0 Potential=0.5 ManualReview=0.2
                           NotVulnerable=0.0 Error=0.0 (Error excluded from the sum)
            PostureScore = 100 - [math]::Min(100, sum(RiskScore_i * StatusWeight_i))

        The result is rounded to one decimal via [math]::Round(x, 1) - the same
        rounding used per-finding - so higher scores mean a better security posture.

        Letter grade: A(90-100) B(80-89) C(70-79) D(60-69) F(<60).

        Findings SHOULD already carry RiskScore (run Get-EscRiskScore first); any
        finding lacking RiskScore is treated as 0. The summary also reports the
        Status counts, a BySeverity breakdown (counted only among Vulnerable and
        Potential findings), and up to 5 TopFindings (highest RiskScore, Vulnerable
        only). The function is deterministic and pure - no clock is read; the caller
        stamps the generation time and may pass it (or any context) via
        -GeneratedContext, which is echoed back untouched.
    .PARAMETER Finding
        The scored Finding [pscustomobject]s.
    .PARAMETER GeneratedContext
        Optional caller-supplied context object (e.g. Domain/Forest/GeneratedAt);
        passed through verbatim onto the summary's GeneratedContext property.
    .OUTPUTS
        [pscustomobject] summary: PostureScore, Grade, Total, Vulnerable, Potential,
        ManualReview, NotVulnerable, Error, BySeverity (hashtable), TopFindings,
        GeneratedContext.
    .EXAMPLE
        $summary = Get-EscPostureScore -Finding ($findings | Get-EscRiskScore)
        # Score every finding, then roll them up into one posture summary.
    .EXAMPLE
        $scored  = Get-EscRiskScore -Finding $findings
        $summary = Get-EscPostureScore -Finding $scored -GeneratedContext $ctx.Meta
        "{0} / 100 -> {1}" -f $summary.PostureScore, $summary.Grade
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Finding,

        [Parameter(Mandatory = $false)]
        [object] $GeneratedContext
    )

    $statusWeight = @{
        'Vulnerable'    = 1.0
        'Potential'     = 0.5
        'ManualReview'  = 0.2
        'NotVulnerable' = 0.0
        'Error'         = 0.0
    }

    $counts = @{
        'Vulnerable'    = 0
        'Potential'     = 0
        'ManualReview'  = 0
        'NotVulnerable' = 0
        'Error'         = 0
    }
    $bySeverity = @{
        'Critical' = 0
        'High'     = 0
        'Medium'   = 0
        'Low'      = 0
        'Info'     = 0
    }

    $total = 0
    $sum   = 0.0

    foreach ($f in $Finding) {
        if ($null -eq $f) { continue }
        $total++

        $status = [string] $f.Status

        if ($counts.ContainsKey($status)) {
            $counts[$status] = $counts[$status] + 1
        }

        $risk = 0.0
        if ($f.PSObject.Properties.Match('RiskScore').Count -gt 0 -and $null -ne $f.RiskScore) {
            $risk = [double] $f.RiskScore
        }

        if ($statusWeight.ContainsKey($status)) {
            $sum += ($risk * $statusWeight[$status])
        }

        if ($status -eq 'Vulnerable' -or $status -eq 'Potential') {
            $sev = [string] $f.Severity
            if ($bySeverity.ContainsKey($sev)) {
                $bySeverity[$sev] = $bySeverity[$sev] + 1
            }
        }
    }

    $penalty  = [math]::Min(100.0, $sum)
    $additive = [math]::Round((100.0 - $penalty), 1)

    $ceiling   = 100.0
    $worstVuln = 'None'
    $vulnSevs  = @()
    foreach ($f in $Finding) {
        if ($null -ne $f -and [string]$f.Status -eq 'Vulnerable') { $vulnSevs += [string]$f.Severity }
    }
    if     ($vulnSevs -contains 'Critical') { $ceiling = 39.0; $worstVuln = 'Critical' }
    elseif ($vulnSevs -contains 'High')     { $ceiling = 69.0; $worstVuln = 'High' }
    elseif ($vulnSevs -contains 'Medium')   { $ceiling = 79.0; $worstVuln = 'Medium' }
    elseif ($vulnSevs -contains 'Low')      { $ceiling = 89.0; $worstVuln = 'Low' }

    $posture = [math]::Round([math]::Min([double] $additive, $ceiling), 1)
    $capped  = ($posture -lt $additive)

    if ($posture -ge 90)      { $grade = 'A' }
    elseif ($posture -ge 80)  { $grade = 'B' }
    elseif ($posture -ge 70)  { $grade = 'C' }
    elseif ($posture -ge 60)  { $grade = 'D' }
    else                      { $grade = 'F' }

    $topFindings = @(
        $Finding |
            Where-Object { $null -ne $_ -and [string]$_.Status -eq 'Vulnerable' } |
            Sort-Object -Property @{ Expression = { [double] $_.RiskScore } } -Descending |
            Select-Object -First 5
    )

    [pscustomobject]@{
        PostureScore     = $posture
        Grade            = $grade
        AdditiveScore    = $additive
        Capped           = $capped
        WorstVulnerableSeverity = $worstVuln
        Total            = $total
        Vulnerable       = $counts['Vulnerable']
        Potential        = $counts['Potential']
        ManualReview     = $counts['ManualReview']
        NotVulnerable    = $counts['NotVulnerable']
        Error            = $counts['Error']
        BySeverity       = $bySeverity
        TopFindings      = $topFindings
        GeneratedContext = $GeneratedContext
    }
}
