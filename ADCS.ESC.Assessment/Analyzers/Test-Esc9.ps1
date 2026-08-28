function Test-Esc9 {
    <#
    .SYNOPSIS
        ESC9 - No Security Extension (per-template CT_FLAG_NO_SECURITY_EXTENSION).
    .DESCRIPTION
        Read-only analyzer. Flags certificate templates that set
        CT_FLAG_NO_SECURITY_EXTENSION (0x00080000) in msPKI-Enrollment-Flag AND
        permit client authentication AND allow enrollment by low-privileged
        principals. Such certs omit the szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2)
        SID binding, enabling authentication as another principal when a domain
        controller does not enforce strong certificate binding.

        Exploitability is cross-referenced against $Context.DcMappings: the attack
        requires at least one DC with StrongCertificateBindingEnforcement < 2.
    .PARAMETER Context
        AssessmentContext pscustomobject.
    .PARAMETER ExtraLowPrivSid
        Additional SID strings to treat as low-privileged.
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

    $reference = 'https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-and-some-fixes-42f9f5f4c142'
    $findings = @()

    $extra = @()
    if ($ExtraLowPrivSid) { $extra += $ExtraLowPrivSid }
    if ($Context.ExtraLowPrivSid) { $extra += $Context.ExtraLowPrivSid }

    if ($null -eq $Context.Templates) {
        return @([pscustomobject]@{
            Id = 'ESC9'; Title = 'ESC9 template data unavailable'; Severity = 'High';
            Status = 'ManualReview'; AffectedObject = 'N/A';
            Evidence = [pscustomobject]@{ Reason = 'Context.Templates was null; no certificate template data collected.' };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'Re-run collection with certificate template read access.';
            Reference = $reference
        })
    }

    $weakDcs = @()
    $dcDataPresent = $false
    if ($Context.DcMappings) {
        foreach ($dc in $Context.DcMappings) {
            if ($dc.Reachable -eq $false) { continue }
            $dcDataPresent = $true
            if ($null -ne $dc.StrongCertificateBindingEnforcement -and [int]$dc.StrongCertificateBindingEnforcement -lt 2) {
                $weakDcs += $dc.DomainController
            }
        }
    }

    foreach ($tmpl in $Context.Templates) {
        $noSecExt = $false
        if ($null -ne $tmpl.NoSecurityExtension) { $noSecExt = [bool]$tmpl.NoSecurityExtension }
        elseif ($null -ne $tmpl.EnrollmentFlag) { $noSecExt = (([int]$tmpl.EnrollmentFlag) -band 0x00080000) -ne 0 }
        if (-not $noSecExt) { continue }

        if (-not (Test-EscEkuAllowsAuth -EkuList $tmpl.EkuList -ApplicationPolicies $tmpl.ApplicationPolicies)) { continue }

        $lowPrivEnrollers = @()
        foreach ($ace in @($tmpl.EnrollPrincipals)) {
            if ($null -eq $ace) { continue }
            if ($ace.AceType -ne 'Allow') { continue }
            $isEnroll = ($ace.Rights -contains 'Enroll') -or ($ace.Rights -contains 'GenericAll')
            if (-not $isEnroll) { continue }
            $isLow = $false
            if ($ace.IsLowPriv) { $isLow = $true } else { $isLow = Test-EscLowPrivPrincipal -Sid $ace.PrincipalSid -ExtraLowPrivSid $extra }
            if ($isLow) { $lowPrivEnrollers += $ace }
        }
        if ($lowPrivEnrollers.Count -eq 0) { continue }

        $principals = @($lowPrivEnrollers | ForEach-Object { if ($_.PrincipalName) { $_.PrincipalName } else { $_.PrincipalSid } } | Select-Object -Unique)

        if ($weakDcs.Count -gt 0) {
            $exploit = 'High'
            $dcNote = "Weak-binding DC(s) present (StrongCertificateBindingEnforcement < 2): $($weakDcs -join ', ')"
        }
        elseif ($dcDataPresent) {
            $exploit = 'Low'
            $dcNote = 'All reachable DCs enforce StrongCertificateBindingEnforcement >= 2; exploitation blocked unless a weak DC exists.'
        }
        else {
            $exploit = 'Medium'
            $dcNote = 'DC binding enforcement unknown (no reachable DcMappings); verify StrongCertificateBindingEnforcement < 2 on a DC.'
        }

        $findings += [pscustomobject]@{
            Id = 'ESC9'
            Title = "Template '$($tmpl.Name)' omits SID security extension (ESC9)"
            Severity = 'High'
            Status = 'Vulnerable'
            AffectedObject = $tmpl.Name
            Evidence = [pscustomobject]@{
                Template            = $tmpl.Name
                DisplayName         = $tmpl.DisplayName
                EnrollmentFlag      = $tmpl.EnrollmentFlag
                NoSecurityExtension = $true
                EkuList             = @($tmpl.EkuList)
                ApplicationPolicies = @($tmpl.ApplicationPolicies)
                PublishedOnCAs      = @($tmpl.PublishedOnCAs)
                LowPrivEnrollers    = $principals
                DcContext           = $dcNote
                Note                = 'Per-template flag. Contrast ESC16 (per-CA DisableExtensionList disables the same extension CA-wide).'
            }
            Principals = $principals
            Exploitability = $exploit
            RiskScore = 0
            Remediation = 'Remove CT_FLAG_NO_SECURITY_EXTENSION from the template, restrict enrollment to trusted principals, and set StrongCertificateBindingEnforcement=2 on all DCs.'
            Reference = $reference
        }
    }

    if ($findings.Count -eq 0) {
        return @([pscustomobject]@{
            Id = 'ESC9'; Title = 'No ESC9 (No Security Extension) templates found'; Severity = 'Info';
            Status = 'NotVulnerable'; AffectedObject = 'All templates';
            Evidence = [pscustomobject]@{ TemplatesChecked = @($Context.Templates).Count };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'None required.'; Reference = $reference
        })
    }

    return $findings
}
