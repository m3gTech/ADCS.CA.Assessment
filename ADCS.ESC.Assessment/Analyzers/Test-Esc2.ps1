function Test-Esc2 {
    <#
    .SYNOPSIS
        ESC2 - Any-Purpose EKU or no-EKU (SubCA-like) template open to low-priv enrollment.
    .DESCRIPTION
        Flags templates whose EKU set is Any-Purpose (2.5.29.37.0) OR completely
        empty (no EKU + no application policy, i.e. a subordinate-CA-style "use for
        anything" certificate), that a low-privileged principal can enroll in
        without manager approval or enrollment-agent signatures. Such a certificate
        can be repurposed for authentication (and more), similar to ESC1 but without
        needing enrollee-supplied SAN.

        Vulnerable (per template) =
          (EKU/AppPolicy contains 2.5.29.37.0 OR both EKU and AppPolicy empty)
          AND a low-priv principal holds Enroll/AutoEnroll
          AND ManagerApprovalRequired == $false
          AND RaSignaturesRequired -lt 1
          AND published on at least one CA.
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

    $reference = 'SpecterOps "Certified Pre-Owned" (ESC2) / Certipy'
    $findings = @()

    $newFinding = {
        param($Title, $Severity, $Status, $Affected, $Evidence, $Principals, $Exploit, $Remediation)
        [pscustomobject]@{
            Id             = 'ESC2'
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
        return @(& $newFinding 'ESC2 - no certificate templates available' 'High' 'ManualReview' 'N/A' `
            ([pscustomobject]@{ Error = 'Context.Templates is empty or unavailable; could not evaluate ESC2.' }) `
            @() 'Theoretical' 'Collect certificate templates and re-run the assessment.')
    }

    foreach ($tpl in $templates) {
        $eku = @($tpl.EkuList)
        $appPol = @($tpl.ApplicationPolicies)
        $hasAnyPurpose = (($eku -contains '2.5.29.37.0') -or ($appPol -contains '2.5.29.37.0'))
        $noEku = (($eku.Count -eq 0) -and ($appPol.Count -eq 0))
        if (-not ($hasAnyPurpose -or $noEku)) { continue }

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

        if ($hasAnyPurpose) { $kind = 'Any-Purpose EKU (2.5.29.37.0)' } else { $kind = 'No EKU / SubCA-like (empty EKU + Application Policy)' }

        $evidence = [pscustomobject]@{
            EkuKind                 = $kind
            EkuList                 = $eku
            ApplicationPolicies     = $appPol
            ManagerApprovalRequired = $false
            RaSignaturesRequired    = [int]$tpl.RaSignaturesRequired
            PublishedOnCAs          = $published
            LowPrivEnrollRights     = @($lowPrivEnrollers | ForEach-Object { '{0}:{1}' -f $_.PrincipalName, ($_.Rights -join '|') })
        }

        $findings += & $newFinding `
            ("ESC2 - template '{0}' is Any-Purpose/No-EKU and open to low-priv enrollment" -f $tpl.Name) `
            'High' 'Vulnerable' $tpl.Name $evidence $principalNames 'High' `
            'Constrain the template EKU to only the required purpose, require manager approval, and restrict enrollment to trusted principals.'
    }

    if ($findings.Count -eq 0) {
        return @(& $newFinding 'ESC2 - no Any-Purpose/No-EKU templates open to low-priv enrollment' 'High' 'NotVulnerable' 'N/A' `
            ([pscustomobject]@{ TemplatesEvaluated = $templates.Count }) @() 'Theoretical' 'No action required for ESC2.')
    }

    return $findings
}
