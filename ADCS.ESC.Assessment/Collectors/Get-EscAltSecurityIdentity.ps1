function Get-EscAltSecurityIdentity {
    <#
    .SYNOPSIS
        Collects account altSecurityIdentities explicit mappings + write ACLs (read-only) for ESC14.
    .DESCRIPTION
        Enumerates user/computer accounts that have a non-empty altSecurityIdentities
        attribute, and reads each account's nTSecurityDescriptor to determine who can
        write that attribute. Test-Esc14 flags weak mapping values (X509:<I>, X509:<S>,
        X509:<RFC822>) and low-priv write access to altSecurityIdentities.

        Emits objects consumed by Test-Esc14:
            Name, DN, Mappings (string[]), WriteAces (Ace[])

        Read-only: LDAP search only. No writes.

        Offline mode: pass -InputObject with records already shaped as the output
        (Name, Mappings[], WriteAces[] of parsed Ace objects); they pass through.
    .PARAMETER Server
        Optional DC/server to bind to.
    .PARAMETER DefaultNamingContext
        Optional domain NC DN (auto-detected from RootDSE when omitted).
    .PARAMETER InputObject
        Optional array of offline records (see description).
    .PARAMETER ExtraLowPrivSid
        Optional extra low-priv SIDs forwarded to the ACL parser.
    .OUTPUTS
        [pscustomobject] AltSecurityIdentity[].
    .EXAMPLE
        Get-EscAltSecurityIdentity -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $DefaultNamingContext,

        [Parameter(Mandatory = $false)]
        [object[]] $InputObject,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @()
    )

    if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
        Write-EscLog -Component 'AltSecId' -Message ("Offline mode: passing through {0} fixture record(s)." -f @($InputObject).Count)
        $out = @()
        foreach ($rec in $InputObject) {
            $out += [pscustomobject]@{
                Name      = [string]$rec.Name
                DN        = [string]$rec.DN
                Mappings  = @($rec.Mappings)
                WriteAces = @($rec.WriteAces)
            }
        }
        return @($out)
    }

    $domainNc = $DefaultNamingContext
    if ([string]::IsNullOrWhiteSpace($domainNc)) {
        $domainNc = Get-EscDefaultNamingContext -Server $Server
    }
    if ([string]::IsNullOrWhiteSpace($domainNc)) {
        Write-EscLog -Component 'AltSecId' -Level Warning -Message 'Could not resolve default naming context; returning empty set.'
        return @()
    }

    $props = @('distinguishedName', 'sAMAccountName', 'name', 'altSecurityIdentities', 'nTSecurityDescriptor')
    $results = Invoke-EscLdapSearch -SearchRoot $domainNc -Filter '(&(altSecurityIdentities=*)(|(objectClass=user)(objectClass=computer)))' -PropertiesToLoad $props -SearchScope Subtree -Server $Server

    $out = @()
    foreach ($r in @($results)) {
        $bag = ConvertTo-EscPropertyBag -SearchResult $r

        $name = ''
        if ($bag.ContainsKey('samaccountname')) { $name = [string]@($bag['samaccountname'])[0] }
        elseif ($bag.ContainsKey('name')) { $name = [string]@($bag['name'])[0] }

        $dn = ''
        if ($bag.ContainsKey('distinguishedname')) { $dn = [string]@($bag['distinguishedname'])[0] }

        $mappings = @()
        if ($bag.ContainsKey('altsecurityidentities')) { $mappings = @($bag['altsecurityidentities']) }

        $writeAces = @()
        if ($bag.ContainsKey('ntsecuritydescriptor')) {
            $sd = @($bag['ntsecuritydescriptor'])[0]
            $aces = ConvertFrom-SecurityDescriptor -SecurityDescriptor $sd -Context AdObject -ExtraLowPrivSid $ExtraLowPrivSid
            foreach ($ace in @($aces)) {
                if ($null -eq $ace) { continue }
                $canWrite = ($ace.Rights -contains 'WriteProperty') -or ($ace.Rights -contains 'GenericWrite') -or ($ace.Rights -contains 'GenericAll') -or ($ace.Rights -contains 'WriteDacl')
                if ($canWrite) { $writeAces += $ace }
            }
        }

        $out += [pscustomobject]@{
            Name      = $name
            DN        = $dn
            Mappings  = @($mappings)
            WriteAces = @($writeAces)
        }
    }

    return @($out)
}
