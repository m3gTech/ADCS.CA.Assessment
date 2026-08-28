function Test-Esc14 {
    <#
    .SYNOPSIS
        ESC14 - Weak or writable altSecurityIdentities explicit certificate mappings.
    .DESCRIPTION
        Read-only analyzer. Two abuse variants:
          Variant B (weak value): a privileged account's altSecurityIdentities uses a
            weak mapping type - X509IssuerSubject (<I><S>), X509SubjectOnly (<S>), or
            X509RFC822 (email) - which an attacker can satisfy with a forged/spoofed
            certificate. Only exploitable when a DC allows weak binding
            (StrongCertificateBindingEnforcement 0/1).
          Variant A (writable ACL): a low-priv principal has write access
            (WriteProperty on altSecurityIdentities / GenericWrite / GenericAll /
            WriteDacl) over a privileged account and can add a strong-but-attacker-
            controlled mapping. Exploitable regardless of DC enforcement.

        Collectors do not enumerate account altSecurityIdentities / DACLs broadly, so
        unless $Context.AltSecurityIdentities is present this analyzer emits
        ManualReview with the exact check.
    .PARAMETER Context
        AssessmentContext pscustomobject.
    .PARAMETER ExtraLowPrivSid
        Additional SID strings to treat as low-privileged (used if mapping data present).
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

    $reference = 'https://www.gradcatrix.com/ (ADCS ESC14 altSecurityIdentities)'

    $weakDcs = @()
    if ($Context.DcMappings) {
        foreach ($dc in $Context.DcMappings) {
            if ($dc.Reachable -eq $false) { continue }
            if ($null -ne $dc.StrongCertificateBindingEnforcement -and [int]$dc.StrongCertificateBindingEnforcement -lt 2) {
                $weakDcs += $dc.DomainController
            }
        }
    }

    $weakTypesNote = @(
        'X509IssuerSubject  (X509:<I>...<S>...)  - WEAK',
        'X509SubjectOnly    (X509:<S>...)        - WEAK',
        'X509RFC822         (X509:<RFC822>email) - WEAK',
        'Strong (safe): X509IssuerSerialNumber (<I><SR>), X509SKI (<SKI>), X509SHA1PublicKey (<SHA1-PUKEY>).'
    )

    $hasData = ($null -ne $Context.AltSecurityIdentities -and @($Context.AltSecurityIdentities).Count -gt 0)

    if (-not $hasData) {
        return @([pscustomobject]@{
            Id = 'ESC14'
            Title = 'ESC14 - altSecurityIdentities mappings not collected (manual)'
            Severity = 'High'
            Status = 'ManualReview'
            AffectedObject = 'Privileged accounts'
            Evidence = [pscustomobject]@{
                Reason = 'No $Context.AltSecurityIdentities collection present; account altSecurityIdentities values and DACLs are not gathered by current collectors.'
                ManualCheck = @(
                    'Enumerate user/computer objects with altSecurityIdentities populated.',
                    'Flag weak mapping types (see WeakMappingTypes).',
                    'Enumerate DACLs on privileged accounts for low-priv WriteProperty (altSecurityIdentities) / GenericWrite / GenericAll / WriteDacl.',
                    'Weak value + a DC with StrongCertificateBindingEnforcement < 2 = exploitable (Variant B); writable ACL = exploitable regardless (Variant A).'
                )
                WeakMappingTypes = $weakTypesNote
                WeakBindingDCs = $weakDcs
                DcContext = if ($weakDcs.Count -gt 0) { "Weak-binding DC(s) present: $($weakDcs -join ', ') - Variant B is live." } else { 'No weak-binding DC observed (or DcMappings absent); Variant A (writable ACL) still applies.' }
            }
            Principals = @()
            Exploitability = 'Theoretical'
            RiskScore = 0
            Remediation = 'Replace weak altSecurityIdentities mappings with strong types (SKI / SHA1PublicKey / IssuerSerialNumber), lock down write access to the attribute, and set StrongCertificateBindingEnforcement=2.'
            Reference = $reference
        })
    }

    $findings = @()
    $extra = @()
    if ($ExtraLowPrivSid) { $extra += $ExtraLowPrivSid }
    if ($Context.ExtraLowPrivSid) { $extra += $Context.ExtraLowPrivSid }

    $weakPrefixes = @('X509:<I>', 'X509:<S>', 'X509:<RFC822>')

    foreach ($acct in $Context.AltSecurityIdentities) {
        $weakMaps = @()
        foreach ($m in @($acct.Mappings)) {
            if (-not $m) { continue }
            $mv = [string]$m
            foreach ($pfx in $weakPrefixes) {
                if ($mv.Replace(' ', '').StartsWith($pfx)) {
                    if ($pfx -eq 'X509:<S>' -and ($mv -match '<SR>' -or $mv -match '<SKI>')) { continue }
                    $weakMaps += $mv
                    break
                }
            }
        }

        $writableAces = @()
        foreach ($ace in @($acct.WriteAces)) {
            if ($null -eq $ace) { continue }
            if ($ace.AceType -ne 'Allow') { continue }
            $canWrite = ($ace.Rights -contains 'WriteProperty') -or ($ace.Rights -contains 'GenericWrite') -or ($ace.Rights -contains 'GenericAll') -or ($ace.Rights -contains 'WriteDacl')
            if (-not $canWrite) { continue }
            $isLow = $false
            if ($ace.IsLowPriv) { $isLow = $true } else { $isLow = Test-EscLowPrivPrincipal -Sid $ace.PrincipalSid -ExtraLowPrivSid $extra }
            if ($isLow) { $writableAces += $ace }
        }

        $variantB = ($weakMaps.Count -gt 0 -and $weakDcs.Count -gt 0)
        $variantA = ($writableAces.Count -gt 0)
        if (-not $variantB -and -not $variantA) { continue }

        $principals = @($writableAces | ForEach-Object { if ($_.PrincipalName) { $_.PrincipalName } else { $_.PrincipalSid } } | Select-Object -Unique)
        if ($variantA) { $exploit = 'High' } else { $exploit = 'Medium' }

        $findings += [pscustomobject]@{
            Id = 'ESC14'
            Title = "Account '$($acct.Name)' has weak/writable altSecurityIdentities (ESC14)"
            Severity = 'High'
            Status = 'Vulnerable'
            AffectedObject = $acct.Name
            Evidence = [pscustomobject]@{
                Account = $acct.Name
                WeakMappings = $weakMaps
                VariantB_WeakValue = $variantB
                VariantA_WritableAcl = $variantA
                WritablePrincipals = $principals
                WeakBindingDCs = $weakDcs
            }
            Principals = $principals
            Exploitability = $exploit
            RiskScore = 0
            Remediation = 'Use strong mapping types, remove low-priv write access to altSecurityIdentities, and enforce StrongCertificateBindingEnforcement=2.'
            Reference = $reference
        }
    }

    if ($findings.Count -eq 0) {
        return @([pscustomobject]@{
            Id = 'ESC14'; Title = 'No ESC14 weak/writable explicit mappings found'; Severity = 'Info';
            Status = 'NotVulnerable'; AffectedObject = 'Accounts';
            Evidence = [pscustomobject]@{ AccountsChecked = @($Context.AltSecurityIdentities).Count };
            Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0;
            Remediation = 'None required.'; Reference = $reference
        })
    }

    return $findings
}
