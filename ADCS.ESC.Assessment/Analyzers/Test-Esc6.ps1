function Test-Esc6 {
    <#
    .SYNOPSIS
        ESC6 - CA honours request-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2).
    .DESCRIPTION
        Flags CAs whose policy-module EditFlags has EDITF_ATTRIBUTESUBJECTALTNAME2
        (0x00040000) set (collector-derived EditFlagsAttributeSanSet == $true). When
        set, the CA embeds a request-supplied SAN (san: request attribute) into the
        issued certificate for ANY template - even templates that build the subject
        from AD - effectively making every client-auth-capable template ESC1-like.

        Vulnerable (per CA) = EditFlagsAttributeSanSet == $true.
        CA unreachable / config missing -> ManualReview.
    .PARAMETER Context
        AssessmentContext pscustomobject. Reads $Context.CaConfigs.
    .PARAMETER ExtraLowPrivSid
        Extra SID strings to treat as low-privileged (unused; kept for signature parity).
    .OUTPUTS
        Finding[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Context,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @()
    )

    $reference = 'SpecterOps "Certified Pre-Owned" (ESC6) / Certipy'
    $findings = @()

    $newFinding = {
        param($Title, $Severity, $Status, $Affected, $Evidence, $Principals, $Exploit, $Remediation)
        [pscustomobject]@{
            Id             = 'ESC6'
            Title          = $Title
            Severity       = $Severity
            Status         = $Status
            AffectedObject = $Affected
            Evidence       = $Evidence
            Principals     = @($Principals)
            Exploitability = $Exploit
            RiskScore      = 0
            Remediation    = $Remediation
            Reference      = $reference
        }
    }

    $caConfigs = @()
    if ($null -ne $Context -and $null -ne $Context.CaConfigs) { $caConfigs = @($Context.CaConfigs) }

    if ($caConfigs.Count -eq 0) {
        return @(& $newFinding 'ESC6 - no CA configuration available' 'Critical' 'ManualReview' 'N/A' `
            ([pscustomobject]@{ Error = 'Context.CaConfigs is empty or unavailable; could not evaluate ESC6.' }) `
            @() 'Theoretical' 'Collect CA configuration (certutil -getreg policy\EditFlags) and re-run.')
    }

    foreach ($ca in $caConfigs) {
        if (-not $ca.Reachable) {
            $findings += & $newFinding `
                ("ESC6 - CA '{0}' configuration unreachable" -f $ca.Name) `
                'Critical' 'ManualReview' $ca.Name `
                ([pscustomobject]@{ Error = 'CA unreachable; EditFlags could not be read. Verify EDITF_ATTRIBUTESUBJECTALTNAME2 manually.'; DnsHostName = $ca.DnsHostName }) `
                @() 'Theoretical' 'Verify certutil -config "<host>\<CA>" -getreg policy\EditFlags manually.'
            continue
        }

        if ($ca.EditFlagsAttributeSanSet) {
            $evidence = [pscustomobject]@{
                EditFlagsAttributeSanSet = $true
                EditFlags                = ('0x{0:X}' -f [int]$ca.EditFlags)
                FlagBit                  = 'EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000)'
                DnsHostName              = $ca.DnsHostName
                Impact                   = 'Any low-priv-enrollable client-auth template on this CA becomes ESC1-like via the san: request attribute.'
            }
            $findings += & $newFinding `
                ("ESC6 - CA '{0}' honours request-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2 set)" -f $ca.Name) `
                'Critical' 'Vulnerable' $ca.Name $evidence @() 'High' `
                'Clear the flag: certutil -config "<host>\<CA>" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2, then restart CertSvc.'
        }
    }

    if ($findings.Count -eq 0) {
        return @(& $newFinding 'ESC6 - no CA honours request-supplied SAN' 'Critical' 'NotVulnerable' 'N/A' `
            ([pscustomobject]@{ CasEvaluated = $caConfigs.Count }) @() 'Theoretical' 'No action required for ESC6.')
    }

    return $findings
}
