function Get-EscOidGroupLink {
    <#
    .SYNOPSIS
        Collects issuance-policy OID -> group links (read-only) for ESC13.
    .DESCRIPTION
        Enumerates msPKI-Enterprise-Oid objects under
            CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,<configNC>
        that have a non-empty msDS-OIDToGroupLink attribute. Each such OID, when it
        appears in a certificate template's IssuancePolicies (msPKI-Certificate-Policy),
        grants membership in the linked group to the enrollee (ESC13).

        Emits objects consumed by Test-Esc13:
            Oid, DisplayName, GroupDn, GroupSid, GroupName, IsPrivilegedGroup

        Read-only: LDAP search only. No writes.

        Offline mode: pass -InputObject with records already shaped as the output
        (Oid + GroupDn/GroupName/GroupSid [+ IsPrivilegedGroup]); they pass through.
    .PARAMETER Server
        Optional DC/server to bind to.
    .PARAMETER ConfigurationNamingContext
        Optional config NC DN (auto-detected from RootDSE when omitted).
    .PARAMETER InputObject
        Optional array of offline records (see description).
    .OUTPUTS
        [pscustomobject] OidGroupLink[].
    .EXAMPLE
        Get-EscOidGroupLink -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $ConfigurationNamingContext,

        [Parameter(Mandatory = $false)]
        [object[]] $InputObject
    )

    if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
        Write-EscLog -Component 'OidGroupLink' -Message ("Offline mode: passing through {0} fixture record(s)." -f @($InputObject).Count)
        $out = @()
        foreach ($rec in $InputObject) {
            $out += [pscustomobject]@{
                Oid               = [string]$rec.Oid
                DisplayName       = [string]$rec.DisplayName
                GroupDn           = [string]$rec.GroupDn
                GroupSid          = [string]$rec.GroupSid
                GroupName         = [string]$rec.GroupName
                IsPrivilegedGroup = [bool]$rec.IsPrivilegedGroup
            }
        }
        return @($out)
    }

    $configNc = $ConfigurationNamingContext
    if ([string]::IsNullOrWhiteSpace($configNc)) {
        $configNc = Get-EscConfigNamingContext -Server $Server
    }
    if ([string]::IsNullOrWhiteSpace($configNc)) {
        Write-EscLog -Component 'OidGroupLink' -Level Warning -Message 'Could not resolve configuration naming context; returning empty set.'
        return @()
    }

    $oidRoot = "CN=OID,CN=Public Key Services,CN=Services,$configNc"
    $props = @('distinguishedName', 'displayName', 'name', 'msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink')

    $results = Invoke-EscLdapSearch -SearchRoot $oidRoot -Filter '(&(objectClass=msPKI-Enterprise-Oid)(msDS-OIDToGroupLink=*))' -PropertiesToLoad $props -SearchScope Subtree -Server $Server

    $out = @()
    foreach ($r in @($results)) {
        $bag = ConvertTo-EscPropertyBag -SearchResult $r
        $oid = ''
        if ($bag.ContainsKey('mspki-cert-template-oid')) { $oid = [string]@($bag['mspki-cert-template-oid'])[0] }

        $groupDn = ''
        if ($bag.ContainsKey('msds-oidtogrouplink')) { $groupDn = [string]@($bag['msds-oidtogrouplink'])[0] }

        $displayName = ''
        if ($bag.ContainsKey('displayname')) { $displayName = [string]@($bag['displayname'])[0] }
        elseif ($bag.ContainsKey('name')) { $displayName = [string]@($bag['name'])[0] }

        $groupSid = $null
        $groupName = $null
        $isPriv = $false
        if (-not [string]::IsNullOrWhiteSpace($groupDn)) {
            try {
                $gProps = @('objectSid', 'sAMAccountName', 'name', 'adminCount')
                $gRes = Invoke-EscLdapSearch -SearchRoot $groupDn -Filter '(objectClass=group)' -PropertiesToLoad $gProps -SearchScope Base -Server $Server
                if (@($gRes).Count -gt 0) {
                    $gBag = ConvertTo-EscPropertyBag -SearchResult @($gRes)[0]
                    if ($gBag.ContainsKey('samaccountname')) { $groupName = [string]@($gBag['samaccountname'])[0] }
                    elseif ($gBag.ContainsKey('name')) { $groupName = [string]@($gBag['name'])[0] }
                    if ($gBag.ContainsKey('objectsid')) {
                        $rawSid = @($gBag['objectsid'])[0]
                        try { $groupSid = (New-Object System.Security.Principal.SecurityIdentifier($rawSid, 0)).Value } catch { $groupSid = $null }
                    }
                    if ($gBag.ContainsKey('admincount') -and [string]@($gBag['admincount'])[0] -eq '1') { $isPriv = $true }
                }
            } catch {
                Write-EscLog -Component 'OidGroupLink' -Level Warning -Message ("Could not resolve linked group '{0}': {1}" -f $groupDn, $_.Exception.Message)
            }
        }

        $out += [pscustomobject]@{
            Oid               = $oid
            DisplayName       = $displayName
            GroupDn           = $groupDn
            GroupSid          = $groupSid
            GroupName         = $groupName
            IsPrivilegedGroup = $isPriv
        }
    }

    return @($out)
}
