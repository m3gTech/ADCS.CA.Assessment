function Test-Esc7 {
    <#
    .SYNOPSIS
        ESC7 - Low-privileged principal holds CA management rights (ManageCA / ManageCertificates).
    .DESCRIPTION
        Flags CAs whose security descriptor grants a low-privileged principal
        ManageCA (CA Administrator) or ManageCertificates (CA Officer). A CA
        Administrator can flip dangerous policy flags (e.g. enable
        EDITF_ATTRIBUTESUBJECTALTNAME2 -> ESC6) and manage the CA; a CA Officer can
        approve pending requests. Either enables privilege escalation.

        Vulnerable (per CA) = any SecurityAce with AceType == Allow AND
          IsLowPriv == $true AND Rights contains ManageCA or ManageCertificates.
        SecurityAces null / CA unreachable -> ManualReview.
    .PARAMETER Context
        AssessmentContext pscustomobject. Reads $Context.CaConfigs.
    .PARAMETER ExtraLowPrivSid
        Extra SID strings to treat as low-privileged (parity; ACE IsLowPriv is precomputed).
    .OUTPUTS
        Finding[]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject] $Context,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @()
    )

    $reference = 'SpecterOps "Certified Pre-Owned" (ESC7) / Certipy'
    $findings = @()

    $newFinding = {
        param($Title, $Severity, $Status, $Affected, $Evidence, $Principals, $Exploit, $Remediation)
        [pscustomobject]@{
            Id             = 'ESC7'
            Title          = $Title
            Severity       = $Severity
            Status         = $Status
            AffectedObject = $Affected
            Evidence       = $Evidence
            Principals     = @($Principals)
            Exploitability = $Exploit
            RiskScore      = 0
            Remediation    = $Remediation
            Reference      = $reference
        }
    }

    $caConfigs = @()
    if ($null -ne $Context -and $null -ne $Context.CaConfigs) { $caConfigs = @($Context.CaConfigs) }

    if ($caConfigs.Count -eq 0) {
        return @(& $newFinding 'ESC7 - no CA configuration available' 'Critical' 'ManualReview' 'N/A' `
            ([pscustomobject]@{ Error = 'Context.CaConfigs is empty or unavailable; could not evaluate ESC7.' }) `
            @() 'Theoretical' 'Collect CA security (certutil -getreg CA\Security) and re-run.')
    }

    foreach ($ca in $caConfigs) {
        if (-not $ca.Reachable -or $null -eq $ca.SecurityAces) {
            $findings += & $newFinding `
                ("ESC7 - CA '{0}' security descriptor unavailable" -f $ca.Name) `
                'Critical' 'ManualReview' $ca.Name `
                ([pscustomobject]@{ Error = 'SecurityAces null or CA unreachable; ManageCA/ManageCertificates grants could not be evaluated.'; Reachable = [bool]$ca.Reachable; DnsHostName = $ca.DnsHostName }) `
                @() 'Theoretical' 'Verify CA security (certutil -config "<host>\<CA>" -getreg CA\Security) manually.'
            continue
        }

        $mgmtAces = @($ca.SecurityAces | Where-Object {
            $_.AceType -eq 'Allow' -and $_.IsLowPriv -and (
                ($_.Rights -contains 'ManageCA') -or ($_.Rights -contains 'ManageCertificates')
            )
        })
        if ($mgmtAces.Count -eq 0) { continue }

        $hasManageCa = (@($mgmtAces | Where-Object { $_.Rights -contains 'ManageCA' }).Count -gt 0)
        if ($hasManageCa) { $exploit = 'High' } else { $exploit = 'Medium' }

        $principalNames = @($mgmtAces | ForEach-Object {
            if ($_.PrincipalName) { $_.PrincipalName } else { $_.PrincipalSid }
        } | Select-Object -Unique)

        $evidence = [pscustomobject]@{
            DnsHostName = $ca.DnsHostName
            ManagementAces = @($mgmtAces | ForEach-Object {
                [pscustomobject]@{
                    Principal  = $_.PrincipalName
                    Sid        = $_.PrincipalSid
                    Rights     = @($_.Rights | Where-Object { @('ManageCA','ManageCertificates') -contains $_ })
                    AccessMask = ('0x{0:X}' -f [int]$_.AccessMask)
                }
            })
            Pivot = [pscustomobject]@{
                EditFlagsAttributeSanSet = [bool]$ca.EditFlagsAttributeSanSet
                DisableExtensionList     = @($ca.DisableExtensionList)
            }
        }

        $findings += & $newFinding `
            ("ESC7 - CA '{0}' grants CA management rights to a low-priv principal" -f $ca.Name) `
            'Critical' 'Vulnerable' $ca.Name $evidence $principalNames $exploit `
            'Remove ManageCA/ManageCertificates from low-privileged principals; grant CA management only to trusted administrators.'
    }

    if ($findings.Count -eq 0) {
        return @(& $newFinding 'ESC7 - no CA grants management rights to low-priv principals' 'Critical' 'NotVulnerable' 'N/A' `
            ([pscustomobject]@{ CasEvaluated = $caConfigs.Count }) @() 'Theoretical' 'No action required for ESC7.')
    }

    return $findings
}
