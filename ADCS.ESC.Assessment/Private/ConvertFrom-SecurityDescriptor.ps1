function ConvertFrom-SecurityDescriptor {
    <#
    .SYNOPSIS
        Translates a security descriptor's DACL into an array of Ace[] objects
        matching the 'Ace' sub-object schema.
    .DESCRIPTION
        Read-only. Accepts raw nTSecurityDescriptor bytes, a base64 string, or an
        already-constructed [System.Security.AccessControl.RawSecurityDescriptor]
        and returns one [pscustomobject] per Allow/Deny ACE in the DACL with:
            PrincipalSid, PrincipalName, IsLowPriv, Rights(string[]),
            AccessMask(int), AceType(Allow|Deny)

        Two access-mask interpretation contexts are supported:
          - 'AdObject'   (default): interprets the mask as Active Directory object
             rights and resolves extended-right ObjectType GUIDs to Enroll /
             AutoEnroll. Also maps WriteDacl, WriteOwner, WriteProperty,
             GenericAll, GenericWrite.
          - 'CaSecurity': interprets the mask as CERTSRV_ACCESS bits used by the
             CA object security descriptor (ManageCA=0x1, ManageCertificates=0x2,
             Enroll=0x200).

        SID -> name resolution is best effort and tolerates failure (PrincipalName
        becomes $null). Low-privilege classification is delegated to
        Test-EscLowPrivPrincipal.
    .PARAMETER SecurityDescriptor
        Raw descriptor: byte[], base64 string, or RawSecurityDescriptor.
    .PARAMETER Context
        'AdObject' (default) or 'CaSecurity'. Controls access-mask translation.
    .PARAMETER ExtraLowPrivSid
        Optional extra SIDs forwarded to Test-EscLowPrivPrincipal.
    .OUTPUTS
        [pscustomobject] Ace records (0..N).
    .EXAMPLE
        ConvertFrom-SecurityDescriptor -SecurityDescriptor $bytes
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object] $SecurityDescriptor,

        [Parameter(Mandatory = $false)]
        [ValidateSet('AdObject', 'CaSecurity')]
        [string] $Context = 'AdObject',

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @()
    )

    $enrollGuid     = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollGuid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    $ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
    $ADS_RIGHT_DS_WRITE_PROP     = 0x00000020
    $WRITE_DAC                   = 0x00040000
    $WRITE_OWNER                 = 0x00080000
    $ADS_RIGHT_GENERIC_ALL       = 0x10000000
    $ADS_RIGHT_GENERIC_WRITE     = 0x40000000
    $CERTSRV_MANAGE_CA           = 0x00000001
    $CERTSRV_MANAGE_CERTS        = 0x00000002
    $CERTSRV_ENROLL              = 0x00000200

    $rsd = $null
    try {
        if ($null -eq $SecurityDescriptor) {
            return @()
        }
        elseif ($SecurityDescriptor -is [System.Security.AccessControl.RawSecurityDescriptor]) {
            $rsd = $SecurityDescriptor
        }
        elseif ($SecurityDescriptor -is [byte[]]) {
            $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($SecurityDescriptor, 0)
        }
        elseif ($SecurityDescriptor -is [string]) {
            $bytes = [System.Convert]::FromBase64String($SecurityDescriptor)
            $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)
        }
        else {
            $bytes = [byte[]] $SecurityDescriptor
            $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)
        }
    }
    catch {
        Write-EscLog -Component 'SDParser' -Level Warning -Message ("Failed to parse security descriptor: {0}" -f $_.Exception.Message)
        return @()
    }

    if ($null -eq $rsd -or $null -eq $rsd.DiscretionaryAcl) {
        return @()
    }

    $results = New-Object System.Collections.ArrayList

    foreach ($ace in $rsd.DiscretionaryAcl) {
        $aceType = $null
        if ($ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowed -or
            $ace.AceType -eq [System.Security.AccessControl.AceType]::AccessAllowedObject) {
            $aceType = 'Allow'
        }
        elseif ($ace.AceType -eq [System.Security.AccessControl.AceType]::AccessDenied -or
                $ace.AceType -eq [System.Security.AccessControl.AceType]::AccessDeniedObject) {
            $aceType = 'Deny'
        }
        else {
            continue
        }

        $sidValue = $null
        try { $sidValue = $ace.SecurityIdentifier.Value } catch { $sidValue = $null }

        $mask = 0
        try { $mask = [int] $ace.AccessMask } catch { $mask = 0 }

        $objectTypeGuid = $null
        $hasObjectType = $false
        try {
            if ($ace.PSObject.Properties.Name -contains 'ObjectAceFlags') {
                if (($ace.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) -ne 0) {
                    $hasObjectType = $true
                    $objectTypeGuid = $ace.ObjectAceType.ToString().ToLowerInvariant()
                }
            }
        }
        catch {
            $hasObjectType = $false
        }

        $rights = New-Object System.Collections.ArrayList

        if ($Context -eq 'CaSecurity') {
            if (($mask -band $CERTSRV_MANAGE_CA) -ne 0)    { [void]$rights.Add('ManageCA') }
            if (($mask -band $CERTSRV_MANAGE_CERTS) -ne 0) { [void]$rights.Add('ManageCertificates') }
            if (($mask -band $CERTSRV_ENROLL) -ne 0)       { [void]$rights.Add('Enroll') }
        }
        else {
            $isGenericAll   = (($mask -band $ADS_RIGHT_GENERIC_ALL) -ne 0)
            $isGenericWrite = (($mask -band $ADS_RIGHT_GENERIC_WRITE) -ne 0)

            if ($isGenericAll)   { [void]$rights.Add('GenericAll') }
            if ($isGenericWrite) { [void]$rights.Add('GenericWrite') }
            if (($mask -band $WRITE_DAC) -ne 0)   { [void]$rights.Add('WriteDacl') }
            if (($mask -band $WRITE_OWNER) -ne 0) { [void]$rights.Add('WriteOwner') }
            if (($mask -band $ADS_RIGHT_DS_WRITE_PROP) -ne 0) { [void]$rights.Add('WriteProperty') }

            if (($mask -band $ADS_RIGHT_DS_CONTROL_ACCESS) -ne 0) {
                if ($hasObjectType) {
                    if ($objectTypeGuid -eq $enrollGuid)     { [void]$rights.Add('Enroll') }
                    elseif ($objectTypeGuid -eq $autoEnrollGuid) { [void]$rights.Add('AutoEnroll') }
                }
                else {
                    [void]$rights.Add('Enroll')
                    [void]$rights.Add('AutoEnroll')
                }
            }

            if ($isGenericAll) {
                if ($rights -notcontains 'Enroll')     { [void]$rights.Add('Enroll') }
                if ($rights -notcontains 'AutoEnroll') { [void]$rights.Add('AutoEnroll') }
            }
        }

        $principalName = $null
        if (-not [string]::IsNullOrWhiteSpace($sidValue)) {
            try {
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sidValue)
                $principalName = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
            }
            catch {
                $principalName = $null
            }
        }

        $isLowPriv = $false
        try {
            $isLowPriv = Test-EscLowPrivPrincipal -Sid $sidValue -ExtraLowPrivSid $ExtraLowPrivSid
        }
        catch {
            $isLowPriv = $false
        }

        $obj = [pscustomobject]@{
            PrincipalSid  = $sidValue
            PrincipalName = $principalName
            IsLowPriv     = $isLowPriv
            Rights        = @($rights.ToArray())
            AccessMask    = $mask
            AceType       = $aceType
        }
        [void]$results.Add($obj)
    }

    return @($results.ToArray())
}
