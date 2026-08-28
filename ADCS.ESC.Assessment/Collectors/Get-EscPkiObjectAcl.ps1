function Get-EscPkiObjectAcl {
    <#
    .SYNOPSIS
        Collects nTSecurityDescriptor ACLs of key AD CS objects (read-only).
    .DESCRIPTION
        Reads the security descriptor of:
          - NTAuthCertificates  (CN=NTAuthCertificates,CN=Public Key Services,...)
          - OID container       (CN=OID,CN=Public Key Services,...)
          - each Enrollment Service (pKIEnrollmentService)
          - each CA object      (certificationAuthority under CN=Certification Authorities)
          - each CA computer object (matched by dNSHostName)
        and maps them to PkiAcl schema
        (ObjectType, DN, OwnerSid, Aces[]).

        Offline mode: pass -InputObject with records of the shape
            @{ ObjectType=..; DN=..; SecurityDescriptor=<base64|bytes> }
    .PARAMETER Server
        Optional DC/server to bind to.
    .PARAMETER ConfigurationNamingContext
        Optional config NC DN (auto-detected from RootDSE when omitted).
    .PARAMETER InputObject
        Optional array of offline records (see description).
    .PARAMETER ExtraLowPrivSid
        Optional extra low-priv SIDs forwarded to the ACL parser.
    .OUTPUTS
        [pscustomobject] PkiAcl[].
    .EXAMPLE
        Get-EscPkiObjectAcl -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $ConfigurationNamingContext,

        [Parameter(Mandatory = $false)]
        [object[]] $InputObject,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @()
    )

    if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
        Write-EscLog -Component 'PkiAcl' -Message ("Offline mode: transforming {0} fixture record(s)." -f @($InputObject).Count)
        $out = @()
        foreach ($rec in $InputObject) {
            $sd = $rec.SecurityDescriptor
            $out += ConvertTo-EscPkiAclObject -ObjectType ([string]$rec.ObjectType) -DN ([string]$rec.DN) -SecurityDescriptor $sd -ExtraLowPrivSid $ExtraLowPrivSid
        }
        return @($out)
    }

    $configNc = $ConfigurationNamingContext
    if ([string]::IsNullOrWhiteSpace($configNc)) {
        $configNc = Get-EscConfigNamingContext -Server $Server
    }
    if ([string]::IsNullOrWhiteSpace($configNc)) {
        Write-EscLog -Component 'PkiAcl' -Level Warning -Message 'Could not resolve configuration naming context; returning empty set.'
        return @()
    }

    $sdProps = @('distinguishedName', 'nTSecurityDescriptor', 'dNSHostName')
    $out = @()

    $emitOne = {
        param($dn, $objType)
        $res = Invoke-EscLdapSearch -SearchRoot $dn -Filter '(objectClass=*)' -Server $Server `
            -PropertiesToLoad $sdProps -SearchScope 'Base'
        if (@($res).Count -gt 0) {
            $bag = ConvertTo-EscPropertyBag -SearchResult $res[0]
            $sd = $null
            if ($bag.ContainsKey('ntsecuritydescriptor')) {
                $v = $bag['ntsecuritydescriptor']
                if ($v -is [System.Array] -and $v.Length -gt 0) { $sd = $v[0] } else { $sd = $v }
            }
            return (ConvertTo-EscPkiAclObject -ObjectType $objType -DN $dn -SecurityDescriptor $sd -ExtraLowPrivSid $ExtraLowPrivSid)
        }
        return $null
    }

    $ntauthDn = 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{0}' -f $configNc
    $o = & $emitOne $ntauthDn 'NTAuthCertificates'
    if ($null -ne $o) { $out += $o }

    $oidDn = 'CN=OID,CN=Public Key Services,CN=Services,{0}' -f $configNc
    $o = & $emitOne $oidDn 'OidContainer'
    if ($null -ne $o) { $out += $o }

    $enrollRoot = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $configNc
    $enrollResults = Invoke-EscLdapSearch -SearchRoot $enrollRoot -Filter '(objectClass=pKIEnrollmentService)' `
        -Server $Server -PropertiesToLoad $sdProps -SearchScope 'OneLevel'
    $caHostNames = @()
    foreach ($r in $enrollResults) {
        $bag = ConvertTo-EscPropertyBag -SearchResult $r
        $dn = ''
        if ($bag.ContainsKey('distinguishedname')) { $dn = [string] @($bag['distinguishedname'])[0] }
        $sd = $null
        if ($bag.ContainsKey('ntsecuritydescriptor')) { $sd = @($bag['ntsecuritydescriptor'])[0] }
        if (-not [string]::IsNullOrWhiteSpace($dn)) {
            $out += ConvertTo-EscPkiAclObject -ObjectType 'EnrollmentService' -DN $dn -SecurityDescriptor $sd -ExtraLowPrivSid $ExtraLowPrivSid
        }
        if ($bag.ContainsKey('dnshostname')) {
            $h = [string] @($bag['dnshostname'])[0]
            if (-not [string]::IsNullOrWhiteSpace($h)) { $caHostNames += $h }
        }
    }

    $caRoot = 'CN=Certification Authorities,CN=Public Key Services,CN=Services,{0}' -f $configNc
    $caResults = Invoke-EscLdapSearch -SearchRoot $caRoot -Filter '(objectClass=certificationAuthority)' `
        -Server $Server -PropertiesToLoad $sdProps -SearchScope 'OneLevel'
    foreach ($r in $caResults) {
        $bag = ConvertTo-EscPropertyBag -SearchResult $r
        $dn = ''
        if ($bag.ContainsKey('distinguishedname')) { $dn = [string] @($bag['distinguishedname'])[0] }
        $sd = $null
        if ($bag.ContainsKey('ntsecuritydescriptor')) { $sd = @($bag['ntsecuritydescriptor'])[0] }
        if (-not [string]::IsNullOrWhiteSpace($dn)) {
            $out += ConvertTo-EscPkiAclObject -ObjectType 'CaObject' -DN $dn -SecurityDescriptor $sd -ExtraLowPrivSid $ExtraLowPrivSid
        }
    }

    $defaultNc = Get-EscDefaultNamingContext -Server $Server
    if (-not [string]::IsNullOrWhiteSpace($defaultNc)) {
        foreach ($caHost in ($caHostNames | Select-Object -Unique)) {
            $filter = '(&(objectClass=computer)(dNSHostName={0}))' -f $caHost
            $compRes = Invoke-EscLdapSearch -SearchRoot $defaultNc -Filter $filter -Server $Server `
                -PropertiesToLoad $sdProps -SearchScope 'Subtree'
            foreach ($r in $compRes) {
                $bag = ConvertTo-EscPropertyBag -SearchResult $r
                $dn = ''
                if ($bag.ContainsKey('distinguishedname')) { $dn = [string] @($bag['distinguishedname'])[0] }
                $sd = $null
                if ($bag.ContainsKey('ntsecuritydescriptor')) { $sd = @($bag['ntsecuritydescriptor'])[0] }
                if (-not [string]::IsNullOrWhiteSpace($dn)) {
                    $out += ConvertTo-EscPkiAclObject -ObjectType 'CaComputer' -DN $dn -SecurityDescriptor $sd -ExtraLowPrivSid $ExtraLowPrivSid
                }
            }
        }
    }
    else {
        Write-EscLog -Component 'PkiAcl' -Level Warning -Message 'Could not resolve default naming context; skipping CA computer ACLs.'
    }

    Write-EscLog -Component 'PkiAcl' -Message ("Collected {0} PKI object ACL record(s)." -f @($out).Count)
    return @($out)
}
