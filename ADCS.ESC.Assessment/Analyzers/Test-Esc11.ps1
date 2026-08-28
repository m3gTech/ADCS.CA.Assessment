function Test-Esc11 {
    <#
    .SYNOPSIS
        ESC11 - Relay to ICertPassage (ICPR) RPC when request encryption is not enforced.
    .DESCRIPTION
        Read-only analyzer over $Context.CaConfigs. A CA is vulnerable when
        IF_ENFORCEENCRYPTICERTREQUEST (0x00000200) is NOT set in InterfaceFlags,
        i.e. EnforceEncryptRequest == $false. An unauthenticated attacker can then
        relay NTLM to the ICertPassage RPC interface to obtain certificates.
        Unreachable CAs -> ManualReview.
    .PARAMETER Context
        AssessmentContext pscustomobject.
    .PARAMETER ExtraLowPrivSid
        Unused for ESC11 (kept for signature uniformity).
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

    $reference = 'https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/'
    $findings = @()

    if ($null -eq $Context.CaConfigs -or @($Context.CaConfigs).Count -eq 0) {
        return @([pscustomobject]@{
            Id = 'ESC11'; Title = 'ESC11 CA configuration data unavailable'; Severity = 'Critical';
            Status = 'ManualReview'; AffectedObject = 'Certificate Authorities';
            Evidence = [pscustomobject]@{ Reason = 'Context.CaConfigs was null/empty; CA InterfaceFlags not collected.' };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'Collect CA\InterfaceFlags via certutil -getreg CA\InterfaceFlags.';
            Reference = $reference
        })
    }

    $anyReachable = $false

    foreach ($ca in $Context.CaConfigs) {
        $caName = $ca.Name

        if ($ca.Reachable -eq $false) {
            $findings += [pscustomobject]@{
                Id = 'ESC11'; Title = "CA '$caName' unreachable - encryption enforcement unknown"; Severity = 'Critical';
                Status = 'ManualReview'; AffectedObject = $caName;
                Evidence = [pscustomobject]@{ Ca = $caName; Reachable = $false; Reason = 'certutil / registry read failed.' };
                Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
                Remediation = 'Manually verify IF_ENFORCEENCRYPTICERTREQUEST on this CA.';
                Reference = $reference
            }
            continue
        }
        $anyReachable = $true

        $enforce = $null
        if ($null -ne $ca.EnforceEncryptRequest) { $enforce = [bool]$ca.EnforceEncryptRequest }
        elseif ($null -ne $ca.InterfaceFlags) { $enforce = (([int]$ca.InterfaceFlags) -band 0x200) -ne 0 }

        if ($null -eq $enforce) {
            $findings += [pscustomobject]@{
                Id = 'ESC11'; Title = "CA '$caName' InterfaceFlags not available"; Severity = 'Critical';
                Status = 'ManualReview'; AffectedObject = $caName;
                Evidence = [pscustomobject]@{ Ca = $caName; InterfaceFlags = $null; Reason = 'Neither EnforceEncryptRequest nor InterfaceFlags populated.' };
                Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
                Remediation = 'Manually verify IF_ENFORCEENCRYPTICERTREQUEST on this CA.';
                Reference = $reference
            }
            continue
        }

        if (-not $enforce) {
            $remoteClosed = $false
            if ($null -ne $ca.InterfaceFlags) { $remoteClosed = (([int]$ca.InterfaceFlags) -band 0x2) -ne 0 }
            if ($remoteClosed) { $exploit = 'Low' } else { $exploit = 'High' }

            $findings += [pscustomobject]@{
                Id = 'ESC11'
                Title = "CA '$caName' does not enforce request encryption (ESC11)"
                Severity = 'Critical'
                Status = 'Vulnerable'
                AffectedObject = $caName
                Evidence = [pscustomobject]@{
                    Ca = $caName
                    DnsHostName = $ca.DnsHostName
                    InterfaceFlags = $ca.InterfaceFlags
                    EnforceEncryptRequest = $false
                    IF_ENFORCEENCRYPTICERTREQUEST = '0x200 unset'
                    RemoteIcertRequestDisabled = $remoteClosed
                    Meaning = 'ICertPassage RPC accepts unencrypted requests - NTLM relay to ICPR possible.'
                }
                Principals = @()
                Exploitability = $exploit
                RiskScore = 0
                Remediation = 'Set IF_ENFORCEENCRYPTICERTREQUEST (certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST) and enable EPA/require SMB signing; restart CertSvc.'
                Reference = $reference
            }
        }
    }

    if ($findings.Count -eq 0) {
        $status = 'NotVulnerable'; $sev = 'Info'
        if (-not $anyReachable) { $status = 'ManualReview'; $sev = 'Critical' }
        return @([pscustomobject]@{
            Id = 'ESC11'; Title = 'All CAs enforce request encryption (no ESC11)'; Severity = $sev;
            Status = $status; AffectedObject = 'Certificate Authorities';
            Evidence = [pscustomobject]@{ CasChecked = @($Context.CaConfigs).Count; AnyReachable = $anyReachable };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'None required.'; Reference = $reference
        })
    }

    return $findings
}
