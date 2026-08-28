function Get-EscRiskScore {
    <#
    .SYNOPSIS
        Fills the RiskScore field on ESC Finding objects (read-only, deterministic).
    .DESCRIPTION
        Computes the per-finding RiskScore from the following deterministic model:

            SeverityBase   : Critical=9.0 High=7.0 Medium=5.0 Low=3.0 Info=1.0
            ExploitMult    : High=1.0 Medium=0.8 Low=0.55 Theoretical=0.35
            RiskScore      = [math]::Round([math]::Min(10.0, SeverityBase * ExploitMult), 1)

        Special Status handling:
          - Status = NotVulnerable            -> RiskScore = 0 (formula not applied)
          - Status = Error                    -> RiskScore = 0 (excluded from posture)
          - Status = ManualReview             -> formula IS applied (score kept); it is
                                                 down-weighted (0.2) in the posture roll-up,
                                                 not zeroed here. Only NotVulnerable maps to 0;
                                                 the ManualReview worked example yields 0.4.
          - Severity is never modified for any status.
          - Missing / unknown Exploitability  -> defaults to the Medium multiplier (0.8)
          - Missing / unknown Severity        -> defaults to the Info base (1.0)

        The function updates only the RiskScore field in place; every other Finding
        field is left exactly as received. It is idempotent - running it twice yields
        the same RiskScore - and pure (no clock, no external state).
    .PARAMETER Finding
        One or more Finding [pscustomobject]s. Accepts pipeline
        input or the -Finding parameter.
    .OUTPUTS
        [pscustomobject] The same Finding objects with RiskScore populated.
    .EXAMPLE
        $scored = $findings | Get-EscRiskScore
        # Fills RiskScore on every finding coming out of the analyzers.
    .EXAMPLE
        Get-EscRiskScore -Finding $findings | Where-Object RiskScore -ge 7.0
        # Score a batch and keep only the high-impact findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [pscustomobject[]] $Finding
    )

    begin {
        $severityBase = @{
            'Critical' = 9.0
            'High'     = 7.0
            'Medium'   = 5.0
            'Low'      = 3.0
            'Info'     = 1.0
        }
        $exploitMultiplier = @{
            'High'        = 1.0
            'Medium'      = 0.8
            'Low'         = 0.55
            'Theoretical' = 0.35
        }
        $defaultMultiplier = 0.8
        $defaultBase       = 1.0
    }

    process {
        foreach ($f in $Finding) {
            if ($null -eq $f) { continue }

            $status = [string] $f.Status

            if ($status -eq 'NotVulnerable' -or $status -eq 'Error') {
                $score = 0.0
            }
            else {
                $sev = [string] $f.Severity
                if (-not [string]::IsNullOrEmpty($sev) -and $severityBase.ContainsKey($sev)) {
                    $base = [double] $severityBase[$sev]
                }
                else {
                    $base = $defaultBase
                }

                $exp = [string] $f.Exploitability
                if (-not [string]::IsNullOrEmpty($exp) -and $exploitMultiplier.ContainsKey($exp)) {
                    $mult = [double] $exploitMultiplier[$exp]
                }
                else {
                    $mult = $defaultMultiplier
                }

                $score = [math]::Round([math]::Min(10.0, ($base * $mult)), 1)
            }

            if ($f.PSObject.Properties.Match('RiskScore').Count -gt 0) {
                $f.RiskScore = $score
            }
            else {
                Add-Member -InputObject $f -MemberType NoteProperty -Name 'RiskScore' -Value $score -Force
            }

            $f
        }
    }
}
