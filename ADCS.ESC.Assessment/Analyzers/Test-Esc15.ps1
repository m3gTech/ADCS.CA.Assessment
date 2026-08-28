function Test-Esc15 {
    <#
    .SYNOPSIS
        ESC15 - EKUwu / arbitrary Application Policies on V1 templates (CVE-2024-49019).
    .DESCRIPTION
        Read-only analyzer. Any schema-version-1 certificate template that a low-priv
        principal may enroll (and that is published on a CA) is vulnerable: the
        attacker injects arbitrary Application Policies (e.g. Client Authentication,
        Certificate Request Agent) into the request, so the template's own EkuList is
        IRRELEVANT. Enrollee-supplies-subject raises exploitability; manager approval
        or RA signatures lower it.
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

    $reference = 'https://www.tenable.com/security/research/tra-2024-49 (CVE-2024-49019 EKUwu)'
    $findings = @()

    $extra = @()
    if ($ExtraLowPrivSid) { $extra += $ExtraLowPrivSid }
    if ($Context.ExtraLowPrivSid) { $extra += $Context.ExtraLowPrivSid }

    if ($null -eq $Context.Templates) {
        return @([pscustomobject]@{
            Id = 'ESC15'; Title = 'ESC15 template data unavailable'; Severity = 'Critical';
            Status = 'ManualReview'; AffectedObject = 'N/A';
            Evidence = [pscustomobject]@{ Reason = 'Context.Templates was null; no certificate template data collected.' };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'Re-run template collection.'; Reference = $reference
        })
    }

    foreach ($tmpl in $Context.Templates) {
        if ($null -eq $tmpl.SchemaVersion -or [int]$tmpl.SchemaVersion -ne 1) { continue }

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

        $published = @($tmpl.PublishedOnCAs)
        $isPublished = ($published.Count -gt 0)

        $principals = @($lowPrivEnrollers | ForEach-Object { if ($_.PrincipalName) { $_.PrincipalName } else { $_.PrincipalSid } } | Select-Object -Unique)

        $ess = $false
        if ($null -ne $tmpl.EnrolleeSuppliesSubject) { $ess = [bool]$tmpl.EnrolleeSuppliesSubject }
        elseif ($null -ne $tmpl.NameFlag) { $ess = (([int]$tmpl.NameFlag) -band 0x1) -ne 0 }

        $approval = [bool]$tmpl.ManagerApprovalRequired
        $raReq = 0
        if ($null -ne $tmpl.RaSignaturesRequired) { $raReq = [int]$tmpl.RaSignaturesRequired }

        if ($ess) { $exploit = 'High' } else { $exploit = 'Medium' }
        if ($approval -or $raReq -gt 0) { $exploit = 'Low' }

        if ($isPublished) {
            $status = 'Vulnerable'
        } else {
            $status = 'Potential'
            if ($exploit -eq 'High') { $exploit = 'Medium' }
        }

        $findings += [pscustomobject]@{
            Id = 'ESC15'
            Title = "V1 template '$($tmpl.Name)' allows Application Policy injection (ESC15/EKUwu)"
            Severity = 'Critical'
            Status = $status
            AffectedObject = $tmpl.Name
            Evidence = [pscustomobject]@{
                Template = $tmpl.Name
                SchemaVersion = 1
                PublishedOnCAs = $published
                EnrolleeSuppliesSubject = $ess
                ManagerApprovalRequired = $approval
                RaSignaturesRequired = $raReq
                LowPrivEnrollers = $principals
                Note = 'EkuList is irrelevant - attacker supplies Application Policies (e.g. Client Auth / Enrollment Agent) in the CSR. CA patch state cannot be confirmed remotely; unpatched CAs are exploitable.'
                CaPatchCaveat = 'If the CA is patched for CVE-2024-49019 the injection is blocked; verify KB patch level on the issuing CA.'
            }
            Principals = $principals
            Exploitability = $exploit
            RiskScore = 0
            Remediation = 'Patch issuing CAs for CVE-2024-49019, retire/replace schema V1 templates, and restrict enrollment to trusted principals.'
            Reference = $reference
        }
    }

    if ($findings.Count -eq 0) {
        return @([pscustomobject]@{
            Id = 'ESC15'; Title = 'No ESC15 (EKUwu) V1 enrollable templates found'; Severity = 'Info';
            Status = 'NotVulnerable'; AffectedObject = 'All templates';
            Evidence = [pscustomobject]@{ TemplatesChecked = @($Context.Templates).Count };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'None required.'; Reference = $reference
        })
    }

    return $findings
}
