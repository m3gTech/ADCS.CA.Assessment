function Test-Esc16 {
    <#
    .SYNOPSIS
        ESC16 - szOID_NTDS_CA_SECURITY_EXT globally disabled on a CA.
    .DESCRIPTION
        Read-only analyzer over $Context.CaConfigs. A CA is vulnerable when its
        DisableExtensionList (policy\DisableExtensionList) contains
        1.3.6.1.4.1.311.25.2 (szOID_NTDS_CA_SECURITY_EXT): the SID security extension
        is then omitted from EVERY certificate the CA issues, CA-wide - the same
        primitive as ESC9 but not scoped to a single template.

        Contrast with ESC9 (per-template CT_FLAG_NO_SECURITY_EXTENSION). Exploitability
        depends on DC strong-binding enforcement (< 2 required), cross-referenced from
        $Context.DcMappings. Unreachable CAs -> ManualReview.
    .PARAMETER Context
        AssessmentContext pscustomobject.
    .PARAMETER ExtraLowPrivSid
        Unused for ESC16 (kept for signature uniformity).
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

    $reference = 'https://github.com/ly4k/Certipy (ESC16 - security extension disabled)'
    $secExtOid = '1.3.6.1.4.1.311.25.2'
    $findings = @()

    if ($null -eq $Context.CaConfigs -or @($Context.CaConfigs).Count -eq 0) {
        return @([pscustomobject]@{
            Id = 'ESC16'; Title = 'ESC16 CA configuration data unavailable'; Severity = 'High';
            Status = 'ManualReview'; AffectedObject = 'Certificate Authorities';
            Evidence = [pscustomobject]@{ Reason = 'Context.CaConfigs was null/empty; DisableExtensionList not collected.' };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'Collect policy\DisableExtensionList via certutil -getreg policy\DisableExtensionList.';
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

    $anyReachable = $false

    foreach ($ca in $Context.CaConfigs) {
        $caName = $ca.Name

        if ($ca.Reachable -eq $false) {
            $findings += [pscustomobject]@{
                Id = 'ESC16'; Title = "CA '$caName' unreachable - DisableExtensionList unknown"; Severity = 'High';
                Status = 'ManualReview'; AffectedObject = $caName;
                Evidence = [pscustomobject]@{ Ca = $caName; Reachable = $false; Reason = 'certutil / registry read failed.' };
                Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
                Remediation = 'Manually verify policy\DisableExtensionList on this CA.';
                Reference = $reference
            }
            continue
        }
        $anyReachable = $true

        $disList = @()
        if ($null -ne $ca.DisableExtensionList) { $disList = @($ca.DisableExtensionList | ForEach-Object { if ($_) { ([string]$_).Trim() } }) }

        $disabled = ($disList -contains $secExtOid)
        if (-not $disabled) { continue }

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
            Id = 'ESC16'
            Title = "CA '$caName' disables the SID security extension CA-wide (ESC16)"
            Severity = 'High'
            Status = 'Vulnerable'
            AffectedObject = $caName
            Evidence = [pscustomobject]@{
                Ca = $caName
                DnsHostName = $ca.DnsHostName
                DisableExtensionList = $disList
                DisabledOid = $secExtOid
                Scope = 'CA-wide - EVERY certificate issued by this CA omits szOID_NTDS_CA_SECURITY_EXT (SID binding).'
                DcContext = $dcNote
                ContrastWithEsc9 = 'ESC9 is per-template (CT_FLAG_NO_SECURITY_EXTENSION); ESC16 is this per-CA DisableExtensionList setting. Any client-auth-capable template on this CA becomes an ESC9-style impersonation vector.'
            }
            Principals = @()
            Exploitability = $exploit
            RiskScore = 0
            Remediation = 'Remove 1.3.6.1.4.1.311.25.2 from policy\DisableExtensionList (certutil -setreg), restart CertSvc, and set StrongCertificateBindingEnforcement=2 on all DCs.'
            Reference = $reference
        }
    }

    if ($findings.Count -eq 0) {
        $status = 'NotVulnerable'; $sev = 'Info'
        if (-not $anyReachable) { $status = 'ManualReview'; $sev = 'High' }
        return @([pscustomobject]@{
            Id = 'ESC16'; Title = 'No CA globally disables the SID security extension (no ESC16)'; Severity = $sev;
            Status = $status; AffectedObject = 'Certificate Authorities';
            Evidence = [pscustomobject]@{ CasChecked = @($Context.CaConfigs).Count; AnyReachable = $anyReachable };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'None required.'; Reference = $reference
        })
    }

    return $findings
}
