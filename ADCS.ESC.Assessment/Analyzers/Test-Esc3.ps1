function Test-Esc3 {
    <#
    .SYNOPSIS
        ESC3 - Enrollment Agent (Certificate-Request-Agent EKU) template open to low-priv enrollment.
    .DESCRIPTION
        Flags templates carrying the Certificate-Request-Agent EKU
        (1.3.6.1.4.1.311.20.2.1) that a low-privileged principal can enroll in
        without manager approval or RA signatures. An enrollment-agent certificate
        lets the holder request certificates ON BEHALF OF other principals. Combined
        with a companion template that accepts enrollment-agent signatures
        (RaSignaturesRequired >= 1 and RaApplicationPolicies contains
        1.3.6.1.4.1.311.20.2.1) and has a client-auth EKU, this yields authentication
        as an arbitrary user.

        Agent template Vulnerable =
          EKU/AppPolicy contains 1.3.6.1.4.1.311.20.2.1
          AND low-priv principal holds Enroll/AutoEnroll
          AND ManagerApprovalRequired == $false
          AND RaSignaturesRequired -lt 1
          AND published.
        The companion (target) template condition is reported in Evidence.
    .PARAMETER Context
        AssessmentContext pscustomobject. Reads $Context.Templates.
    .PARAMETER ExtraLowPrivSid
        Extra SID strings to treat as low-privileged.
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

    $reference = 'SpecterOps "Certified Pre-Owned" (ESC3) / Certipy'
    $ENROLLMENT_AGENT_OID = '1.3.6.1.4.1.311.20.2.1'
    $findings = @()

    $newFinding = {
        param($Title, $Severity, $Status, $Affected, $Evidence, $Principals, $Exploit, $Remediation)
        [pscustomobject]@{
            Id             = 'ESC3'
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

    $templates = @()
    if ($null -ne $Context -and $null -ne $Context.Templates) { $templates = @($Context.Templates) }

    if ($templates.Count -eq 0) {
        return @(& $newFinding 'ESC3 - no certificate templates available' 'Critical' 'ManualReview' 'N/A' `
            ([pscustomobject]@{ Error = 'Context.Templates is empty or unavailable; could not evaluate ESC3.' }) `
            @() 'Theoretical' 'Collect certificate templates and re-run the assessment.')
    }

    $companionTargets = @($templates | Where-Object {
        ([int]$_.RaSignaturesRequired -ge 1) -and
        (@($_.RaApplicationPolicies) -contains $ENROLLMENT_AGENT_OID) -and
        (Test-EscEkuAllowsAuth -EkuList $_.EkuList -ApplicationPolicies $_.ApplicationPolicies)
    })
    $companionNames = @($companionTargets | ForEach-Object { $_.Name })

    foreach ($tpl in $templates) {
        $eku = @($tpl.EkuList)
        $appPol = @($tpl.ApplicationPolicies)
        if (-not (($eku -contains $ENROLLMENT_AGENT_OID) -or ($appPol -contains $ENROLLMENT_AGENT_OID))) { continue }

        if ($tpl.ManagerApprovalRequired) { continue }
        if ([int]$tpl.RaSignaturesRequired -ge 1) { continue }

        $lowPrivEnrollers = @($tpl.EnrollPrincipals | Where-Object {
            $_.AceType -eq 'Allow' -and $_.IsLowPriv -and (
                ($_.Rights -contains 'Enroll') -or ($_.Rights -contains 'GenericAll')
            )
        })
        if ($lowPrivEnrollers.Count -eq 0) { continue }

        $published = @($tpl.PublishedOnCAs)
        if ($published.Count -eq 0) { continue }

        $principalNames = @($lowPrivEnrollers | ForEach-Object {
            if ($_.PrincipalName) { $_.PrincipalName } else { $_.PrincipalSid }
        } | Select-Object -Unique)

        if ($companionNames.Count -gt 0) { $exploit = 'High' } else { $exploit = 'Medium' }

        $evidence = [pscustomobject]@{
            CertificateRequestAgentEku = $ENROLLMENT_AGENT_OID
            EkuList                    = $eku
            ApplicationPolicies        = $appPol
            ManagerApprovalRequired    = $false
            RaSignaturesRequired       = [int]$tpl.RaSignaturesRequired
            PublishedOnCAs             = $published
            LowPrivEnrollRights        = @($lowPrivEnrollers | ForEach-Object { '{0}:{1}' -f $_.PrincipalName, ($_.Rights -join '|') })
            CompanionTargetTemplates   = $companionNames
            CompanionCondition         = 'A target template with RaSignaturesRequired>=1, RaApplicationPolicies containing 1.3.6.1.4.1.311.20.2.1, and a client-auth EKU completes the on-behalf-of chain.'
        }

        $findings += & $newFinding `
            ("ESC3 - enrollment-agent template '{0}' open to low-priv enrollment" -f $tpl.Name) `
            'Critical' 'Vulnerable' $tpl.Name $evidence $principalNames $exploit `
            'Restrict enrollment on Certificate-Request-Agent templates, require manager approval, and limit which templates accept enrollment-agent signatures via issuance requirements.'
    }

    if ($findings.Count -eq 0) {
        return @(& $newFinding 'ESC3 - no enrollment-agent templates open to low-priv enrollment' 'Critical' 'NotVulnerable' 'N/A' `
            ([pscustomobject]@{ TemplatesEvaluated = $templates.Count; CompanionTargetsPresent = $companionNames }) @() 'Theoretical' `
            'No action required for ESC3.')
    }

    return $findings
}
