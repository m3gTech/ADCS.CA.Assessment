function ConvertTo-EscPkiAclObject {
    <#
    .SYNOPSIS
        Pure transform: object DN + security descriptor -> PkiAcl schema object.
    .DESCRIPTION
        Produces a PkiAcl object (ObjectType, DN, OwnerSid,
        Aces[]) from a raw nTSecurityDescriptor. No live calls; unit-testable.
    .PARAMETER ObjectType
        One of NTAuthCertificates|OidContainer|EnrollmentService|CaObject|CaComputer.
    .PARAMETER DN
        Distinguished name of the object.
    .PARAMETER SecurityDescriptor
        Raw descriptor (byte[]/base64/RawSecurityDescriptor) or $null.
    .PARAMETER ExtraLowPrivSid
        Optional extra low-priv SIDs forwarded to the ACL parser.
    .OUTPUTS
        [pscustomobject] PkiAcl
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('NTAuthCertificates', 'OidContainer', 'EnrollmentService', 'CaObject', 'CaComputer')]
        [string] $ObjectType,

        [Parameter(Mandatory = $true)]
        [string] $DN,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object] $SecurityDescriptor,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @()
    )

    $ownerSid = $null
    $aces = @()

    if ($null -ne $SecurityDescriptor) {
        $rsd = $null
        try {
            if ($SecurityDescriptor -is [System.Security.AccessControl.RawSecurityDescriptor]) {
                $rsd = $SecurityDescriptor
            }
            elseif ($SecurityDescriptor -is [byte[]]) {
                $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($SecurityDescriptor, 0)
            }
            elseif ($SecurityDescriptor -is [string]) {
                $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor(([System.Convert]::FromBase64String($SecurityDescriptor)), 0)
            }
        }
        catch {
            $rsd = $null
        }

        if ($null -ne $rsd) {
            try { if ($null -ne $rsd.Owner) { $ownerSid = $rsd.Owner.Value } } catch { $ownerSid = $null }
            $aces = @(ConvertFrom-SecurityDescriptor -SecurityDescriptor $rsd -Context 'AdObject' -ExtraLowPrivSid $ExtraLowPrivSid)
        }
    }

    return [pscustomobject]@{
        ObjectType = $ObjectType
        DN         = $DN
        OwnerSid   = $ownerSid
        Aces       = @($aces)
    }
}
