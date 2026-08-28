function Test-Esc10 {
    <#
    .SYNOPSIS
        ESC10 - Weak Certificate Mappings (per-DC).
    .DESCRIPTION
        Read-only analyzer over $Context.DcMappings. Two cases:
          Case 1 (Kerberos): StrongCertificateBindingEnforcement == 0
            (Kdc\StrongCertificateBindingEnforcement) - disables strong binding,
            allowing certificate-to-account mapping abuse.
          Case 2 (Schannel): WeakSchannelMapping == $true, i.e.
            (CertificateMappingMethods -band 0x4) - UPN mapping enabled
            (SCHANNEL\CertificateMappingMethods).
        One finding per affected DC (a DC can be flagged for both cases).
        Unreachable DCs -> ManualReview.
    .PARAMETER Context
        AssessmentContext pscustomobject.
    .PARAMETER ExtraLowPrivSid
        Unused for ESC10 (kept for signature uniformity).
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

    if ($null -eq $Context.DcMappings -or @($Context.DcMappings).Count -eq 0) {
        return @([pscustomobject]@{
            Id = 'ESC10'; Title = 'ESC10 DC mapping data unavailable'; Severity = 'High';
            Status = 'ManualReview'; AffectedObject = 'Domain Controllers';
            Evidence = [pscustomobject]@{ Reason = 'Context.DcMappings was null/empty; DC registry values not collected.' };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'Collect Kdc\StrongCertificateBindingEnforcement and SCHANNEL\CertificateMappingMethods from each DC.';
            Reference = $reference
        })
    }

    $anyReachable = $false

    foreach ($dc in $Context.DcMappings) {
        $dcName = $dc.DomainController

        if ($dc.Reachable -eq $false) {
            $findings += [pscustomobject]@{
                Id = 'ESC10'; Title = "DC '$dcName' unreachable - mapping enforcement unknown"; Severity = 'High';
                Status = 'ManualReview'; AffectedObject = $dcName;
                Evidence = [pscustomobject]@{ DomainController = $dcName; Reachable = $false; Reason = 'Remote registry read failed.' };
                Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
                Remediation = 'Manually verify StrongCertificateBindingEnforcement and CertificateMappingMethods on this DC.';
                Reference = $reference
            }
            continue
        }
        $anyReachable = $true

        if ($null -ne $dc.StrongCertificateBindingEnforcement -and [int]$dc.StrongCertificateBindingEnforcement -eq 0) {
            $findings += [pscustomobject]@{
                Id = 'ESC10'
                Title = "DC '$dcName' has StrongCertificateBindingEnforcement=0 (ESC10 Case 1)"
                Severity = 'High'
                Status = 'Vulnerable'
                AffectedObject = $dcName
                Evidence = [pscustomobject]@{
                    DomainController = $dcName
                    Case = 'Kerberos (StrongCertificateBindingEnforcement)'
                    StrongCertificateBindingEnforcement = 0
                    Meaning = '0=Disabled. Certificate SAN/UPN can be mapped to arbitrary accounts (combine with altSecurityIdentities / ESC9).'
                }
                Principals = @()
                Exploitability = 'High'
                RiskScore = 0
                Remediation = 'Set Kdc\StrongCertificateBindingEnforcement=2 (Full Enforcement) after remediating weak certificate mappings.'
                Reference = $reference
            }
        }

        $weakSchannel = $false
        if ($null -ne $dc.WeakSchannelMapping) { $weakSchannel = [bool]$dc.WeakSchannelMapping }
        elseif ($null -ne $dc.CertificateMappingMethods) { $weakSchannel = (([int]$dc.CertificateMappingMethods) -band 0x4) -ne 0 }

        if ($weakSchannel) {
            $findings += [pscustomobject]@{
                Id = 'ESC10'
                Title = "DC '$dcName' enables weak Schannel UPN mapping (ESC10 Case 2)"
                Severity = 'High'
                Status = 'Vulnerable'
                AffectedObject = $dcName
                Evidence = [pscustomobject]@{
                    DomainController = $dcName
                    Case = 'Schannel (CertificateMappingMethods)'
                    CertificateMappingMethods = $dc.CertificateMappingMethods
                    UpnBitSet = $true
                    Meaning = '0x4 (UPN) mapping enabled - a certificate with a spoofable UPN can authenticate over Schannel as the victim.'
                }
                Principals = @()
                Exploitability = 'High'
                RiskScore = 0
                Remediation = 'Remove the 0x4 (UPN) bit from SCHANNEL\CertificateMappingMethods; prefer strong mapping methods only.'
                Reference = $reference
            }
        }
    }

    if ($findings.Count -eq 0) {
        $status = 'NotVulnerable'; $sev = 'Info'
        if (-not $anyReachable) { $status = 'ManualReview'; $sev = 'High' }
        return @([pscustomobject]@{
            Id = 'ESC10'; Title = 'No ESC10 weak certificate mappings detected'; Severity = $sev;
            Status = $status; AffectedObject = 'Domain Controllers';
            Evidence = [pscustomobject]@{ DcsChecked = @($Context.DcMappings).Count; AnyReachable = $anyReachable };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'None required.'; Reference = $reference
        })
    }

    return $findings
}
