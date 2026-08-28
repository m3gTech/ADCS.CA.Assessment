function ConvertTo-EscTemplateObject {
    <#
    .SYNOPSIS
        Pure transform: raw certificate-template attribute bag -> Template schema.
    .DESCRIPTION
        Maps a property bag of AD certificate-template attributes to the
        Get-EscCertificateTemplate output schema. Contains no
        live calls, so it can be unit-tested with fixture data.

        The property bag ($Property) is a hashtable whose keys are (lowercased)
        LDAP attribute names and whose values are either scalars or arrays. The
        nTSecurityDescriptor may be supplied as raw byte[] or a base64 string
        (either under the 'ntsecuritydescriptor' key or via -SecurityDescriptor).
    .PARAMETER Property
        Hashtable of attribute name (lowercase) -> value(s).
    .PARAMETER SecurityDescriptor
        Optional explicit descriptor (byte[]/base64/RawSecurityDescriptor). If not
        provided, the 'ntsecuritydescriptor' key of $Property is used.
    .PARAMETER ExtraLowPrivSid
        Optional extra low-priv SIDs forwarded to the ACL parser.
    .OUTPUTS
        [pscustomobject] Template
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Property,

        [Parameter(Mandatory = $false)]
        [object] $SecurityDescriptor,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @()
    )

    $getFirst = {
        param($name)
        $key = $name.ToLowerInvariant()
        if ($Property.ContainsKey($key)) {
            $v = $Property[$key]
            if ($v -is [System.Array]) {
                if ($v.Length -gt 0) { return $v[0] }
                return $null
            }
            return $v
        }
        return $null
    }
    $getAll = {
        param($name)
        $key = $name.ToLowerInvariant()
        if ($Property.ContainsKey($key)) {
            $v = $Property[$key]
            if ($null -eq $v) { return @() }
            if ($v -is [System.Array]) { return @($v) }
            return @($v)
        }
        return @()
    }
    $toInt = {
        param($val)
        if ($null -eq $val) { return 0 }
        try { return [int] $val } catch { }
        try { return [int] [long] $val } catch { }
        return 0
    }

    $name        = [string] (& $getFirst 'cn')
    if ([string]::IsNullOrWhiteSpace($name)) { $name = [string] (& $getFirst 'name') }
    $displayName = [string] (& $getFirst 'displayName')
    $oid         = [string] (& $getFirst 'msPKI-Cert-Template-OID')
    $schemaVer   = & $toInt (& $getFirst 'msPKI-Template-Schema-Version')

    $nameFlag        = & $toInt (& $getFirst 'msPKI-Certificate-Name-Flag')
    $enrollmentFlag  = & $toInt (& $getFirst 'msPKI-Enrollment-Flag')
    $raSig           = & $toInt (& $getFirst 'msPKI-RA-Signature')

    $ekuList             = @(& $getAll 'pKIExtendedKeyUsage')
    $appPolicies         = @(& $getAll 'msPKI-Certificate-Application-Policy')
    $raAppPolicies       = @(& $getAll 'msPKI-RA-Application-Policies')
    $issuancePolicies    = @(& $getAll 'msPKI-Certificate-Policy')

    $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
    $CT_FLAG_NO_SECURITY_EXTENSION     = 0x80000
    $CT_FLAG_PEND_ALL_REQUESTS         = 0x2

    $enrolleeSuppliesSubject = (($nameFlag -band $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0)
    $noSecurityExtension     = (($enrollmentFlag -band $CT_FLAG_NO_SECURITY_EXTENSION) -ne 0)
    $managerApprovalRequired = (($enrollmentFlag -band $CT_FLAG_PEND_ALL_REQUESTS) -ne 0)

    $sd = $SecurityDescriptor
    if ($null -eq $sd) {
        $sd = & $getFirst 'ntSecurityDescriptor'
    }

    $allAces = @()
    if ($null -ne $sd) {
        $allAces = @(ConvertFrom-SecurityDescriptor -SecurityDescriptor $sd -Context 'AdObject' -ExtraLowPrivSid $ExtraLowPrivSid)
    }

    $enrollPrincipals = @($allAces | Where-Object {
        $_.AceType -eq 'Allow' -and (
            ($_.Rights -contains 'Enroll') -or
            ($_.Rights -contains 'AutoEnroll') -or
            ($_.Rights -contains 'GenericAll')
        )
    })
    $writePrincipals = @($allAces | Where-Object {
        $_.AceType -eq 'Allow' -and (
            ($_.Rights -contains 'WriteDacl') -or
            ($_.Rights -contains 'WriteOwner') -or
            ($_.Rights -contains 'WriteProperty') -or
            ($_.Rights -contains 'GenericWrite') -or
            ($_.Rights -contains 'GenericAll')
        )
    })

    $raw = @{
        NameFlag            = $nameFlag
        EnrollmentFlag      = $enrollmentFlag
        DistinguishedName   = [string] (& $getFirst 'distinguishedName')
        AllAces             = $allAces
    }

    return [pscustomobject]@{
        Name                    = $name
        DisplayName             = $displayName
        Oid                     = $oid
        SchemaVersion           = $schemaVer
        EnrolleeSuppliesSubject = $enrolleeSuppliesSubject
        EkuList                 = @($ekuList)
        ApplicationPolicies     = @($appPolicies)
        EnrollmentFlag          = $enrollmentFlag
        NameFlag                = $nameFlag
        RaSignaturesRequired    = $raSig
        RaApplicationPolicies   = @($raAppPolicies)
        NoSecurityExtension     = $noSecurityExtension
        ManagerApprovalRequired = $managerApprovalRequired
        IssuancePolicies        = @($issuancePolicies)
        PublishedOnCAs          = @()
        EnrollPrincipals        = @($enrollPrincipals)
        WritePrincipals         = @($writePrincipals)
        Raw                     = $raw
    }
}
