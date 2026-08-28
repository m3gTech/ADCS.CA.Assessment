function Test-Esc8 {
    <#
    .SYNOPSIS
        ESC8 - NTLM relay to AD CS Web Enrollment / CES-CEP.
    .DESCRIPTION
        Flags CA web-enrollment endpoints that accept NTLM authentication without
        adequate channel binding, allowing an attacker to relay coerced NTLM
        authentication (e.g. from a DC) to the endpoint and enrol a certificate on
        the victim's behalf.

        Vulnerable (per endpoint) = Reachable == $true AND NtlmSupported == $true
          AND (Scheme == 'http' OR EpaEnabled == $false).
        NtlmSupported == $true AND EpaEnabled == $null (EPA undetermined over HTTPS)
          -> ManualReview (per ESC8 doc). EpaEnabled == $true over HTTPS -> NotVulnerable.
    .PARAMETER Context
        AssessmentContext pscustomobject. Reads $Context.WebEndpoints.
    .PARAMETER ExtraLowPrivSid
        Extra SID strings (unused; kept for signature parity).
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

    $reference = 'SpecterOps "Certified Pre-Owned" (ESC8) / Certipy / PetitPotam'
    $findings = @()

    $newFinding = {
        param($Title, $Severity, $Status, $Affected, $Evidence, $Principals, $Exploit, $Remediation)
        [pscustomobject]@{
            Id             = 'ESC8'
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

    $endpoints = @()
    if ($null -ne $Context -and $null -ne $Context.WebEndpoints) { $endpoints = @($Context.WebEndpoints) }

    if ($endpoints.Count -eq 0) {
        return @(& $newFinding 'ESC8 - no web-enrollment endpoints available' 'Critical' 'ManualReview' 'N/A' `
            ([pscustomobject]@{ Error = 'Context.WebEndpoints is empty or unavailable; could not evaluate ESC8.' }) `
            @() 'Theoretical' 'Enumerate CA web-enrollment endpoints (/certsrv, CES/CEP) and re-run.')
    }

    $sawSignal = $false

    foreach ($ep in $endpoints) {
        if (-not $ep.Reachable) { continue }
        if (-not $ep.NtlmSupported) { continue }
        $sawSignal = $true

        $httpScheme = ($ep.Scheme -eq 'http')
        $epaOff     = ($ep.EpaEnabled -eq $false)

        if ($httpScheme -or $epaOff) {
            if ($httpScheme) { $reason = 'HTTP scheme (no channel binding possible; EPA moot)' } else { $reason = 'EPA disabled (EpaEnabled=$false)' }
            $evidence = [pscustomobject]@{
                CaName        = $ep.CaName
                Url           = $ep.Url
                Scheme        = $ep.Scheme
                NtlmSupported = $true
                EpaEnabled    = $ep.EpaEnabled
                CesCepPresent = [bool]$ep.CesCepPresent
                Reason        = $reason
            }
            $findings += & $newFinding `
                ("ESC8 - web-enrollment endpoint '{0}' relays NTLM ({1})" -f $ep.Url, $reason) `
                'Critical' 'Vulnerable' $ep.Url $evidence @() 'High' `
                'Disable NTLM on enrollment endpoints, serve over HTTPS only, and require Extended Protection for Authentication (EPA=Require); enable RPC/LDAP signing and channel binding.'
        }
        elseif ($null -eq $ep.EpaEnabled) {
            $evidence = [pscustomobject]@{
                CaName        = $ep.CaName
                Url           = $ep.Url
                Scheme        = $ep.Scheme
                NtlmSupported = $true
                EpaEnabled    = $null
                CesCepPresent = [bool]$ep.CesCepPresent
                Note          = 'NTLM enabled but EPA state could not be determined over HTTPS; verify Extended Protection on the IIS site.'
            }
            $findings += & $newFinding `
                ("ESC8 - endpoint '{0}' accepts NTLM; EPA state undetermined" -f $ep.Url) `
                'Critical' 'ManualReview' $ep.Url $evidence @() 'Medium' `
                'Confirm Extended Protection = Required on the IIS Windows Authentication settings for this endpoint.'
        }
    }

    if ($findings.Count -eq 0) {
        if ($sawSignal) { $detail = 'Reachable NTLM endpoints found, but all enforce HTTPS + EPA.' } else { $detail = 'No reachable NTLM-capable endpoints found.' }
        return @(& $newFinding 'ESC8 - no relayable web-enrollment endpoints' 'Critical' 'NotVulnerable' 'N/A' `
            ([pscustomobject]@{ EndpointsEvaluated = $endpoints.Count; Detail = $detail }) @() 'Theoretical' 'No action required for ESC8.')
    }

    return $findings
}
