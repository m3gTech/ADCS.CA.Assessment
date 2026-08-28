function Get-EscCaRoleAssignment {
    <#
    .SYNOPSIS
        Summarizes CA management-role holders (Manage CA / Issue and Manage
        Certificates) per CA and flags any assignment outside the default groups.
    .DESCRIPTION
        Reads the parsed CA security descriptor (Context.CaConfigs[].SecurityAces)
        and, for every Allow ACE that grants ManageCA (CA Administrator) and/or
        ManageCertificates (Certificate Manager / "Issue and Manage Certificates"),
        emits one row per principal. Each row is marked IsDefault when the principal
        is one of the well-known privileged holders present on a fresh Enterprise CA:

            - BUILTIN\Administrators   (S-1-5-32-544)
            - Domain Admins            (S-1-5-21-<domain>-512)
            - Enterprise Admins        (S-1-5-21-<domain>-519)
            - Local SYSTEM             (S-1-5-18)   [benign machine principal]

        Anything else holding a management right is a non-default assignment and is
        surfaced for review. This is presentation/inventory data; the ESC7 analyzer
        still independently flags the low-privileged subset as Vulnerable.

        Read-only: consumes already-collected ACEs, performs no directory or CA I/O.
    .PARAMETER CaConfig
        CA descriptor objects (Name, DnsHostName, Reachable, SecurityAces[]).
    .PARAMETER ExtraDefaultSid
        Additional SID strings to treat as default/expected (e.g. an environment's
        sanctioned Tier-0 PKI admin group) so they are not flagged as non-default.
    .OUTPUTS
        [pscustomobject] per CA:
            Name, DnsHostName, Reachable, AcesAvailable(bool),
            NonDefaultCount(int), Roles(object[]) where each role is
            { Principal, Sid, ManageCA(bool), ManageCertificates(bool),
              IsDefault(bool), IsLowPriv(bool) }.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]] $CaConfig = @(),

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraDefaultSid = @()
    )

    # Well-known default holders of CA management rights on a fresh Enterprise CA.
    $extra = @($ExtraDefaultSid | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim().ToUpperInvariant() })

    $isDefaultSid = {
        param($Sid)
        if ([string]::IsNullOrWhiteSpace($Sid)) { return $false }
        $s = $Sid.Trim().ToUpperInvariant()
        if ($s -eq 'S-1-5-32-544') { return $true }   # BUILTIN\Administrators
        if ($s -eq 'S-1-5-18')     { return $true }   # Local SYSTEM (benign)
        # Domain Admins (RID 512) / Enterprise Admins (RID 519) under any domain.
        if ($s -match '^S-1-5-21-[0-9-]+-(512|519)$') { return $true }
        if ($extra -contains $s) { return $true }
        return $false
    }

    $out = @()
    foreach ($ca in @($CaConfig)) {
        if ($null -eq $ca) { continue }

        $reachable = [bool]$ca.Reachable
        $aces = $null
        if ($ca.PSObject.Properties.Match('SecurityAces').Count -gt 0) { $aces = $ca.SecurityAces }
        $acesAvailable = ($null -ne $aces)

        $roles = @()
        if ($acesAvailable) {
            # Collapse per principal: a SID may appear in multiple ACEs.
            $byPrincipal = [ordered]@{}
            foreach ($ace in @($aces)) {
                if ($null -eq $ace) { continue }
                if ($ace.AceType -ne 'Allow') { continue }
                $hasCa   = (@($ace.Rights) -contains 'ManageCA')
                $hasCert = (@($ace.Rights) -contains 'ManageCertificates')
                if (-not ($hasCa -or $hasCert)) { continue }

                $sid = [string]$ace.PrincipalSid
                $key = $sid
                if ([string]::IsNullOrWhiteSpace($key)) { $key = [string]$ace.PrincipalName }
                if ([string]::IsNullOrWhiteSpace($key)) { continue }

                if (-not $byPrincipal.Contains($key)) {
                    $byPrincipal[$key] = [pscustomobject]@{
                        Principal          = [string]$ace.PrincipalName
                        Sid                = $sid
                        ManageCA           = $false
                        ManageCertificates = $false
                        IsDefault          = (& $isDefaultSid $sid)
                        IsLowPriv          = [bool]$ace.IsLowPriv
                    }
                }
                $row = $byPrincipal[$key]
                if ($hasCa)   { $row.ManageCA = $true }
                if ($hasCert) { $row.ManageCertificates = $true }
                if ($ace.IsLowPriv) { $row.IsLowPriv = $true }
            }
            # Non-default first, then low-priv, then name - most interesting on top.
            $roles = @($byPrincipal.Values | Sort-Object `
                @{ Expression = { -not $_.IsDefault }; Descending = $true }, `
                @{ Expression = { [bool]$_.IsLowPriv }; Descending = $true }, `
                @{ Expression = { if ($_.Principal) { $_.Principal } else { $_.Sid } }; Descending = $false })
        }

        $nonDefault = @($roles | Where-Object { -not $_.IsDefault }).Count

        $out += [pscustomobject]@{
            Name            = [string]$ca.Name
            DnsHostName     = [string]$ca.DnsHostName
            Reachable       = $reachable
            AcesAvailable   = $acesAvailable
            NonDefaultCount = [int]$nonDefault
            Roles           = @($roles)
        }
    }

    return $out
}
