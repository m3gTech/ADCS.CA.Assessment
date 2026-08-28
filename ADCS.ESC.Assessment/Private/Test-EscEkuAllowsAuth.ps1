function Test-EscEkuAllowsAuth {
    <#
    .SYNOPSIS
        Returns $true when a certificate template's EKU / Application Policy set
        permits client authentication (i.e. the cert could be used to authenticate
        as a domain principal).
    .DESCRIPTION
        Pure function (no external calls). PowerShell 5.1 compatible.

        A certificate is authentication-capable when ANY of its Extended Key Usage
        or Application Policy OIDs is an authentication-enabling OID, OR when it has
        NO EKU restriction at all (empty EKU + empty Application Policies = usable
        for any purpose, subordinate-CA style).

        Authentication-enabling OIDs:
          1.3.6.1.5.5.7.3.2      Client Authentication
          1.3.6.1.5.2.3.4        PKINIT Client Authentication
          1.3.6.1.4.1.311.20.2.2 Smart Card Logon
          2.5.29.37.0            Any Purpose
    .PARAMETER EkuList
        Array of EKU OID strings from the template (Get-EscCertificateTemplate.EkuList).
    .PARAMETER ApplicationPolicies
        Optional array of Application Policy OID strings
        (Get-EscCertificateTemplate.ApplicationPolicies). Considered together with
        EkuList, since either can carry the auth OID.
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Test-EscEkuAllowsAuth -EkuList @('1.3.6.1.5.5.7.3.2')   # -> $true
    .EXAMPLE
        Test-EscEkuAllowsAuth -EkuList @() -ApplicationPolicies @()   # -> $true (no EKU)
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string[]] $EkuList = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string[]] $ApplicationPolicies = @()
    )

    $authOids = @(
        '1.3.6.1.5.5.7.3.2',
        '1.3.6.1.5.2.3.4',
        '1.3.6.1.4.1.311.20.2.2',
        '2.5.29.37.0'
    )

    $eku = @()
    if ($null -ne $EkuList) {
        foreach ($o in $EkuList) {
            if (-not [string]::IsNullOrWhiteSpace($o)) { $eku += $o.Trim() }
        }
    }
    $appPol = @()
    if ($null -ne $ApplicationPolicies) {
        foreach ($o in $ApplicationPolicies) {
            if (-not [string]::IsNullOrWhiteSpace($o)) { $appPol += $o.Trim() }
        }
    }

    if ($eku.Count -eq 0 -and $appPol.Count -eq 0) {
        return $true
    }

    $combined = @($eku + $appPol)
    foreach ($oid in $combined) {
        if ($authOids -contains $oid) {
            return $true
        }
    }

    return $false
}
