function Test-Esc13 {
    <#
    .SYNOPSIS
        ESC13 - OID Group Link (issuance policy mapped to a privileged group).
    .DESCRIPTION
        Read-only analyzer. A certificate template whose IssuancePolicies
        (msPKI-Certificate-Policy) reference an msPKI-Enterprise-Oid object that
        carries msDS-OIDToGroupLink pointing at a privileged group grants that group
        membership to anyone who enrolls. If such a template allows low-priv
        enrollment and client authentication, it is an ESC13 escalation.

        The OID->group link values come from $Context.OidGroupLinks when a dedicated
        collector populated it (entries with an OID and a linked group). $Context.PkiAcls
        OidContainer entries only carry ACLs, not the link value, so when no
        OidGroupLinks collection exists this analyzer emits ManualReview describing
        exactly what to enumerate.
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

    $reference = 'https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53'
    $findings = @()

    $extra = @()
    if ($ExtraLowPrivSid) { $extra += $ExtraLowPrivSid }
    if ($Context.ExtraLowPrivSid) { $extra += $Context.ExtraLowPrivSid }

    $hasLinks = ($null -ne $Context.OidGroupLinks -and @($Context.OidGroupLinks).Count -gt 0)

    if (-not $hasLinks) {
        return @([pscustomobject]@{
            Id = 'ESC13'
            Title = 'ESC13 - OID-to-group link data not collected (manual)'
            Severity = 'High'
            Status = 'ManualReview'
            AffectedObject = 'msPKI-Enterprise-Oid objects'
            Evidence = [pscustomobject]@{
                Reason = 'No $Context.OidGroupLinks collection present; PkiAcls OidContainer entries carry ACLs only, not msDS-OIDToGroupLink values.'
                ManualCheck = @(
                    'Enumerate CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,<forest> for msPKI-Enterprise-Oid objects with msDS-OIDToGroupLink set.',
                    'Resolve each linked group DN and assess whether it is privileged.',
                    'Match the linked OID against each template IssuancePolicies (msPKI-Certificate-Policy).',
                    'A matching template with low-priv Enroll/AutoEnroll + client-auth EKU is ESC13 Vulnerable.'
                )
                TemplatesWithIssuancePolicies = @($Context.Templates | Where-Object { $_.IssuancePolicies -and @($_.IssuancePolicies).Count -gt 0 } | ForEach-Object { [pscustomobject]@{ Template = $_.Name; IssuancePolicies = @($_.IssuancePolicies) } })
            }
            Principals = @()
            Exploitability = 'Theoretical'
            RiskScore = 0
            Remediation = 'Remove msDS-OIDToGroupLink from OIDs mapped to privileged groups, or restrict enrollment on templates carrying those issuance policies.'
            Reference = $reference
        })
    }

    if ($null -eq $Context.Templates) {
        return @([pscustomobject]@{
            Id = 'ESC13'; Title = 'ESC13 template data unavailable'; Severity = 'High';
            Status = 'ManualReview'; AffectedObject = 'N/A';
            Evidence = [pscustomobject]@{ Reason = 'OidGroupLinks present but Context.Templates null; cannot cross-reference.' };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'Re-run template collection.'; Reference = $reference
        })
    }

    $linkByOid = @{}
    foreach ($link in $Context.OidGroupLinks) {
        $oid = $link.Oid
        if (-not $oid) { $oid = $link.OidValue }
        if (-not $oid) { continue }
        $linkByOid[[string]$oid] = $link
    }

    foreach ($tmpl in $Context.Templates) {
        $pols = @($tmpl.IssuancePolicies)
        if ($pols.Count -eq 0) { continue }

        $matched = @()
        foreach ($p in $pols) {
            if ($p -and $linkByOid.ContainsKey([string]$p)) { $matched += $linkByOid[[string]$p] }
        }
        if ($matched.Count -eq 0) { continue }

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
        $linkedGroups = @($matched | ForEach-Object { if ($_.GroupName) { $_.GroupName } elseif ($_.GroupDn) { $_.GroupDn } else { $_.GroupSid } })

        $priv = $false
        foreach ($m in $matched) { if ($m.IsPrivilegedGroup -or $m.Privileged) { $priv = $true } }
        if ($priv) { $exploit = 'High' } else { $exploit = 'Medium' }

        $findings += [pscustomobject]@{
            Id = 'ESC13'
            Title = "Template '$($tmpl.Name)' issuance policy links to group membership (ESC13)"
            Severity = 'High'
            Status = 'Vulnerable'
            AffectedObject = $tmpl.Name
            Evidence = [pscustomobject]@{
                Template = $tmpl.Name
                IssuancePolicies = $pols
                LinkedOids = @($matched | ForEach-Object { if ($_.Oid) { $_.Oid } else { $_.OidValue } })
                LinkedGroups = $linkedGroups
                LowPrivEnrollers = $principals
                Note = 'Enrolling this template grants membership in the linked group for the duration of the certificate; verify the group is privileged.'
            }
            Principals = $principals
            Exploitability = $exploit
            RiskScore = 0
            Remediation = 'Remove msDS-OIDToGroupLink from the OID, or restrict enrollment on this template to trusted principals.'
            Reference = $reference
        }
    }

    if ($findings.Count -eq 0) {
        return @([pscustomobject]@{
            Id = 'ESC13'; Title = 'No ESC13 OID-group-link escalation templates found'; Severity = 'Info';
            Status = 'NotVulnerable'; AffectedObject = 'All templates';
            Evidence = [pscustomobject]@{ TemplatesChecked = @($Context.Templates).Count; OidLinksChecked = @($Context.OidGroupLinks).Count };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'None required.'; Reference = $reference
        })
    }

    return $findings
}
