function Test-Esc1 {
    <#
    .SYNOPSIS
        ESC1 - Enrollee-supplied Subject Alternative Name on an authentication template.
    .DESCRIPTION
        Flags certificate templates that let a low-privileged enrollee both supply
        an arbitrary subject (SAN) AND obtain a certificate usable for
        authentication, without manager approval or enrollment-agent signatures.
        Such a template lets any low-priv principal request a certificate for an
        arbitrary user (e.g. a Domain Admin UPN) and authenticate as them.

        Vulnerable (per template) =
          EnrolleeSuppliesSubject == $true
          AND EKU allows authentication (client-auth / smartcard / PKINIT /
              Any-Purpose, or empty EKU list)
          AND ManagerApprovalRequired == $false
          AND RaSignaturesRequired -lt 1
          AND a low-priv principal holds Enroll/AutoEnroll
          AND the template is published on at least one CA.
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

    $reference = 'SpecterOps "Certified Pre-Owned" (ESC1) / Certipy'
    $findings = @()

    $newFinding = {
        param($Title, $Severity, $Status, $Affected, $Evidence, $Principals, $Exploit, $Remediation)
        [pscustomobject]@{
            Id             = 'ESC1'
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
        return @(& $newFinding 'ESC1 - no certificate templates available' 'Critical' 'ManualReview' 'N/A' `
            ([pscustomobject]@{ Error = 'Context.Templates is empty or unavailable; could not evaluate ESC1.' }) `
            @() 'Theoretical' 'Collect certificate templates and re-run the assessment.')
    }

    $extra = @()
    if ($ExtraLowPrivSid) { $extra += $ExtraLowPrivSid }
    if ($null -ne $Context.ExtraLowPrivSid) { $extra += $Context.ExtraLowPrivSid }

    foreach ($tpl in $templates) {
        if (-not $tpl.EnrolleeSuppliesSubject) { continue }

        $combinedEku = @()
        if ($tpl.EkuList) { $combinedEku += $tpl.EkuList }
        if ($tpl.ApplicationPolicies) { $combinedEku += $tpl.ApplicationPolicies }
        if (-not (Test-EscEkuAllowsAuth -EkuList $tpl.EkuList -ApplicationPolicies $tpl.ApplicationPolicies)) { continue }

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

        $authEkus = @($combinedEku | Where-Object {
            @('1.3.6.1.5.5.7.3.2','1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.2.3.4','2.5.29.37.0') -contains $_
        } | Select-Object -Unique)

        $evidence = [pscustomobject]@{
            EnrolleeSuppliesSubject = $true
            NameFlag                = ('0x{0:X}' -f [int]$tpl.NameFlag)
            EkuList                 = @($tpl.EkuList)
            ApplicationPolicies     = @($tpl.ApplicationPolicies)
            AuthEkusMatched         = if ($authEkus.Count -gt 0) { $authEkus } else { @('<empty EKU list - any purpose>') }
            ManagerApprovalRequired = $false
            RaSignaturesRequired    = [int]$tpl.RaSignaturesRequired
            PublishedOnCAs          = $published
            LowPrivEnrollRights     = @($lowPrivEnrollers | ForEach-Object { '{0}:{1}' -f $_.PrincipalName, ($_.Rights -join '|') })
        }

        $findings += & $newFinding `
            ("ESC1 - template '{0}' allows enrollee-supplied SAN on an auth certificate" -f $tpl.Name) `
            'Critical' 'Vulnerable' $tpl.Name $evidence $principalNames 'High' `
            'Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, require manager approval or enrollment-agent signatures, and restrict enrollment to trusted principals.'
    }

    if ($findings.Count -eq 0) {
        return @(& $newFinding 'ESC1 - no enrollee-supplied-SAN authentication templates found' 'Critical' 'NotVulnerable' 'N/A' `
            ([pscustomobject]@{ TemplatesEvaluated = $templates.Count }) @() 'Theoretical' `
            'No action required for ESC1.')
    }

    return $findings
}
