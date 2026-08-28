function Test-Esc12 {
    <#
    .SYNOPSIS
        ESC12 - Shell/Admin access to a CA whose keys live in an HSM (e.g. YubiHSM
        with default PIN / auth-key).
    .DESCRIPTION
        Read-only analyzer. ESC12 abuse (extracting/using CA private keys via an
        HSM with weak PIN or default auth-key, or via host shell access) can only be
        confirmed LOCALLY on the CA host. Remote collection can at most surface the
        attack surface (HSM KSP provider name), never confirm exploitability.

        This analyzer therefore always emits Status=ManualReview describing the exact
        local indicators to verify; it never claims Vulnerable from remote data alone.
    .PARAMETER Context
        AssessmentContext pscustomobject.
    .PARAMETER ExtraLowPrivSid
        Unused for ESC12 (kept for signature uniformity).
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

    $reference = 'https://pkisolutions.com/blog/ (ADCS ESC12 / YubiHSM default credentials)'

    $indicators = @(
        "KSP provider name 'YubiHSM Key Storage Provider' (or other HSM KSP) on the CA signing key.",
        "Registry HKLM\SOFTWARE\Yubico\YubiHSM\ and yubihsm-connector.yaml for cleartext PIN.",
        "Default YubiHSM auth-key (ID 1 / password 'password').",
        "Local Administrators / interactive shell access to the CA host (allows raw key or CertSvc abuse)."
    )

    $cas = @()
    if ($Context.EnrollmentServices) { $cas += @($Context.EnrollmentServices | ForEach-Object { $_.Name }) }
    if ($Context.CaConfigs) { $cas += @($Context.CaConfigs | ForEach-Object { $_.Name }) }
    $cas = @($cas | Where-Object { $_ } | Select-Object -Unique)

    $affected = 'Certificate Authorities'
    if ($cas.Count -gt 0) { $affected = ($cas -join ', ') }

    return @([pscustomobject]@{
        Id = 'ESC12'
        Title = 'ESC12 - verify HSM/host key-protection posture on CA(s) (manual)'
        Severity = 'Medium'
        Status = 'ManualReview'
        AffectedObject = $affected
        Evidence = [pscustomobject]@{
            CertificateAuthorities = $cas
            LocalIndicatorsToCheck = $indicators
            Note = 'Remote AD CS collection cannot read HSM PIN/auth-key or host access; confirmation is local-only. Never auto-flag Vulnerable.'
        }
        Principals = @()
        Exploitability = 'Theoretical'
        RiskScore = 0
        Remediation = 'Change default HSM auth-key/PIN, store secrets outside cleartext config, and restrict local admin/shell access on CA hosts.'
        Reference = $reference
    })
}
