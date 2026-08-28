function Get-EscCertPublisher {
    <#
    .SYNOPSIS
        Enumerates members of the domain 'Cert Publishers' group (read-only, live).
    .DESCRIPTION
        Resolves the Cert Publishers group by its well-known RID (517), which is
        locale-independent, and falls back to a CN match. Reads the group's member
        list via LDAP (search only) and resolves each member to its computer /
        principal identity:
            Name, DnsHostName, SamAccountName, DN, ObjectClass

        Cert Publishers normally contains the computer object of every Enterprise CA;
        comparing it against the Enrollment Services objects surfaces stale, missing,
        or rogue CA hosts. Live-only (requires a reachable domain); returns @() on
        any failure.
    .PARAMETER Server
        Optional DC/server to bind to.
    .PARAMETER DefaultNamingContext
        Optional default (domain) NC DN (auto-detected from RootDSE when omitted).
    .OUTPUTS
        [pscustomobject] CertPublisherMember[] (possibly empty).
    .EXAMPLE
        Get-EscCertPublisher -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $DefaultNamingContext
    )

    $dnc = $DefaultNamingContext
    if ([string]::IsNullOrWhiteSpace($dnc)) { $dnc = Get-EscDefaultNamingContext -Server $Server }
    if ([string]::IsNullOrWhiteSpace($dnc)) {
        Write-EscLog -Component 'CertPublishers' -Level Warning -Message 'No default naming context; returning empty set.'
        return @()
    }

    $prefix = 'LDAP://'
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $prefix = 'LDAP://{0}/' -f $Server }

    $groupRes = $null
    try {
        $domEntry = New-Object System.DirectoryServices.DirectoryEntry(('{0}{1}' -f $prefix, $dnc))
        $sidBytes = $domEntry.Properties['objectSid'].Value
        try { $domEntry.Dispose() } catch { }
        if ($null -ne $sidBytes) {
            $domSid = New-Object System.Security.Principal.SecurityIdentifier([byte[]]$sidBytes, 0)
            $grpSid = '{0}-517' -f $domSid.Value
            $res = @(Invoke-EscLdapSearch -SearchRoot $dnc -Filter ('(objectSid={0})' -f $grpSid) -Server $Server `
                -PropertiesToLoad @('distinguishedName', 'member', 'cn') -SearchScope 'Subtree')
            if ($res.Count -gt 0) { $groupRes = $res[0] }
        }
    }
    catch {
        Write-EscLog -Component 'CertPublishers' -Level Warning -Message ("RID 517 lookup failed: {0}" -f $_.Exception.Message)
    }

    if ($null -eq $groupRes) {
        $res = @(Invoke-EscLdapSearch -SearchRoot $dnc -Filter '(&(objectClass=group)(cn=Cert Publishers))' -Server $Server `
            -PropertiesToLoad @('distinguishedName', 'member', 'cn') -SearchScope 'Subtree')
        if ($res.Count -gt 0) { $groupRes = $res[0] }
    }

    if ($null -eq $groupRes) {
        Write-EscLog -Component 'CertPublishers' -Level Warning -Message 'Cert Publishers group not found.'
        return @()
    }

    $memberDns = @()
    try { $memberDns = @($groupRes.Properties['member']) } catch { $memberDns = @() }

    $out = @()
    foreach ($mdn in $memberDns) {
        $m = [string]$mdn
        if ([string]::IsNullOrWhiteSpace($m)) { continue }
        try {
            $mres = @(Invoke-EscLdapSearch -SearchRoot $m -Filter '(objectClass=*)' -Server $Server `
                -PropertiesToLoad @('cn', 'dNSHostName', 'sAMAccountName', 'objectClass', 'distinguishedName') -SearchScope 'Base')
            if ($mres.Count -eq 0) { continue }
            $bag = ConvertTo-EscPropertyBag -SearchResult $mres[0]

            $get = {
                param($k)
                if ($bag.ContainsKey($k)) {
                    $v = $bag[$k]
                    if ($v -is [System.Array]) { if ($v.Length -gt 0) { return [string]$v[0] } else { return '' } }
                    return [string]$v
                }
                return ''
            }
            $oc = @()
            if ($bag.ContainsKey('objectclass')) { $oc = @($bag['objectclass']) }
            $ocLast = ''
            if ($oc.Count -gt 0) { $ocLast = [string]$oc[$oc.Count - 1] }

            $out += [pscustomobject]@{
                Name           = (& $get 'cn')
                DnsHostName    = (& $get 'dnshostname')
                SamAccountName = (& $get 'samaccountname')
                DN             = $m
                ObjectClass    = $ocLast
            }
        }
        catch {
            Write-EscLog -Component 'CertPublishers' -Level Warning -Message ("Failed to resolve member {0}: {1}" -f $m, $_.Exception.Message)
        }
    }

    Write-EscLog -Component 'CertPublishers' -Message ("Cert Publishers group has {0} resolved member(s)." -f @($out).Count)
    return @($out)
}
