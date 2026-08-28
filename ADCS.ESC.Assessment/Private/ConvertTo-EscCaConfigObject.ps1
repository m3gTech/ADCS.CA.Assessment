function ConvertTo-EscCaConfigObject {
    <#
    .SYNOPSIS
        Pure transform: raw certutil -getreg text -> CaConfig schema object.
    .DESCRIPTION
        Builds a CaConfig object from captured certutil output.
        No live calls, so it is unit-testable with fixture strings.

        $RegText is a hashtable keyed by the value path that was queried:
            'policy\EditFlags', 'CA\InterfaceFlags', 'policy\DisableExtensionList',
            'CA\Security', 'CA\PolicyModules\Active' (optional)
        Each value is the raw stdout string from certutil -getreg for that value.
    .PARAMETER Name
        CA common name.
    .PARAMETER DnsHostName
        CA host DNS name.
    .PARAMETER RegText
        Hashtable of value path -> raw certutil text.
    .PARAMETER Reachable
        Whether the CA host was reachable. When $false, numeric/ACL fields are null.
    .PARAMETER ExtraLowPrivSid
        Optional extra low-priv SIDs forwarded to the ACL parser.
    .OUTPUTS
        [pscustomobject] CaConfig
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $false)]
        [string] $DnsHostName,

        [Parameter(Mandatory = $false)]
        [hashtable] $RegText = @{},

        [Parameter(Mandatory = $false)]
        [bool] $Reachable = $true,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [byte[]] $SecurityDescriptorBytes = $null
    )

    $EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
    $IF_ENFORCEENCRYPTICERTREQUEST  = 0x00000200

    $editFlags        = $null
    $editFlagsSan     = $null
    $interfaceFlags   = $null
    $enforceEncrypt   = $null
    $disableExtList   = $null
    $securityAces     = $null
    $policyModule     = $null

    $get = {
        param($path)
        if ($RegText.ContainsKey($path)) { return [string] $RegText[$path] }
        return $null
    }

    if ($Reachable) {
        $t = & $get 'policy\EditFlags'
        if ($null -ne $t) {
            $val = ConvertFrom-CertutilRegistry -Text $t -ValueName 'EditFlags'
            if ($null -ne $val) {
                $editFlags = [int] $val
                $editFlagsSan = (($editFlags -band $EDITF_ATTRIBUTESUBJECTALTNAME2) -ne 0)
            }
        }

        $t = & $get 'CA\InterfaceFlags'
        if ($null -ne $t) {
            $val = ConvertFrom-CertutilRegistry -Text $t -ValueName 'InterfaceFlags'
            if ($null -ne $val) {
                $interfaceFlags = [int] $val
                $enforceEncrypt = (($interfaceFlags -band $IF_ENFORCEENCRYPTICERTREQUEST) -ne 0)
            }
        }

        $t = & $get 'policy\DisableExtensionList'
        if ($null -ne $t) {
            $val = ConvertFrom-CertutilRegistry -Text $t -ValueName 'DisableExtensionList'
            if ($null -ne $val) {
                $disableExtList = @($val)
            }
            else {
                $disableExtList = @()
            }
        }

        if ($null -ne $SecurityDescriptorBytes -and $SecurityDescriptorBytes.Length -gt 0) {
            $securityAces = @(ConvertFrom-SecurityDescriptor -SecurityDescriptor $SecurityDescriptorBytes -Context 'CaSecurity' -ExtraLowPrivSid $ExtraLowPrivSid)
        }
        else {
            $t = & $get 'CA\Security'
            if ($null -ne $t) {
                $bytes = ConvertFrom-CertutilRegistry -Text $t -ValueName 'Security'
                if ($null -ne $bytes -and $bytes -is [byte[]] -and $bytes.Length -gt 0) {
                    $securityAces = @(ConvertFrom-SecurityDescriptor -SecurityDescriptor $bytes -Context 'CaSecurity' -ExtraLowPrivSid $ExtraLowPrivSid)
                }
            }
        }

        $t = & $get 'CA\PolicyModules\Active'
        if ($null -ne $t) {
            $val = ConvertFrom-CertutilRegistry -Text $t -ValueName 'Active'
            if ($null -ne $val) { $policyModule = [string] $val }
        }
    }

    return [pscustomobject]@{
        Name                      = $Name
        DnsHostName               = $DnsHostName
        EditFlags                 = $editFlags
        EditFlagsAttributeSanSet  = $editFlagsSan
        InterfaceFlags            = $interfaceFlags
        EnforceEncryptRequest     = $enforceEncrypt
        DisableExtensionList      = $disableExtList
        SecurityAces              = $securityAces
        PolicyModule              = $policyModule
        Reachable                 = $Reachable
    }
}
