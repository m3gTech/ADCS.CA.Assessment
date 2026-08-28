function Test-Esc5 {
    <#
    .SYNOPSIS
        ESC5 - Dangerous ACL on a PKI object (CA, NTAuth, OID container, CA computer).
    .DESCRIPTION
        Flags AD PKI objects on which a low-privileged principal holds a write-class
        right (WriteDacl / WriteOwner / WriteProperty / GenericWrite / GenericAll), or
        which are owned by a low-privileged principal. Control of these objects
        (Enrollment Service, CA object, NTAuthCertificates, OID container, CA computer
        account) permits broad AD CS compromise - e.g. publishing a rogue CA cert to
        NTAuth, or taking over the CA host.

        Vulnerable (per object) = any Ace with AceType == Allow AND IsLowPriv == $true
          AND Rights intersects {WriteDacl, WriteOwner, WriteProperty, GenericWrite,
          GenericAll}; OR OwnerSid is a low-priv principal.
    .PARAMETER Context
        AssessmentContext pscustomobject. Reads $Context.PkiAcls.
    .PARAMETER ExtraLowPrivSid
        Extra SID strings to treat as low-privileged.
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

    $reference = 'SpecterOps "Certified Pre-Owned" (ESC5) / Certipy'
    $writeRights = @('WriteDacl', 'WriteOwner', 'WriteProperty', 'GenericWrite', 'GenericAll')
    $findings = @()

    $newFinding = {
        param($Title, $Severity, $Status, $Affected, $Evidence, $Principals, $Exploit, $Remediation)
        [pscustomobject]@{
            Id             = 'ESC5'
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

    $acls = @()
    if ($null -ne $Context -and $null -ne $Context.PkiAcls) { $acls = @($Context.PkiAcls) }

    if ($acls.Count -eq 0) {
        return @(& $newFinding 'ESC5 - no PKI object ACLs available' 'High' 'ManualReview' 'N/A' `
            ([pscustomobject]@{ Error = 'Context.PkiAcls is empty or unavailable; could not evaluate ESC5.' }) `
            @() 'Theoretical' 'Collect PKI object ACLs and re-run the assessment.')
    }

    $extra = @()
    if ($ExtraLowPrivSid) { $extra += $ExtraLowPrivSid }
    if ($null -ne $Context.ExtraLowPrivSid) { $extra += $Context.ExtraLowPrivSid }

    foreach ($obj in $acls) {
        $badAces = @($obj.Aces | Where-Object {
            $_.AceType -eq 'Allow' -and $_.IsLowPriv -and (@($_.Rights | Where-Object { $writeRights -contains $_ }).Count -gt 0)
        })

        $ownerLowPriv = $false
        if ($obj.OwnerSid) { $ownerLowPriv = Test-EscLowPrivPrincipal -Sid $obj.OwnerSid -ExtraLowPrivSid $extra }

        if ($badAces.Count -eq 0 -and -not $ownerLowPriv) { continue }

        $principalNames = @()
        $principalNames += @($badAces | ForEach-Object { if ($_.PrincipalName) { $_.PrincipalName } else { $_.PrincipalSid } })
        if ($ownerLowPriv) { $principalNames += ('OWNER:{0}' -f $obj.OwnerSid) }
        $principalNames = @($principalNames | Select-Object -Unique)

        $evidence = [pscustomobject]@{
            ObjectType    = $obj.ObjectType
            DN            = $obj.DN
            DangerousAces = @($badAces | ForEach-Object {
                [pscustomobject]@{
                    Principal  = $_.PrincipalName
                    Sid        = $_.PrincipalSid
                    Rights     = @($_.Rights)
                    AccessMask = ('0x{0:X}' -f [int]$_.AccessMask)
                }
            })
            OwnerSid       = $obj.OwnerSid
            OwnerIsLowPriv = $ownerLowPriv
        }

        $findings += & $newFinding `
            ("ESC5 - {0} object '{1}' has a low-priv-writable ACL" -f $obj.ObjectType, $obj.DN) `
            'High' 'Vulnerable' $obj.DN $evidence $principalNames 'High' `
            'Remove write/owner rights from low-privileged principals on this PKI object; restrict the ACL to trusted administrative groups.'
    }

    if ($findings.Count -eq 0) {
        return @(& $newFinding 'ESC5 - no PKI objects with low-priv-writable ACLs' 'High' 'NotVulnerable' 'N/A' `
            ([pscustomobject]@{ ObjectsEvaluated = $acls.Count }) @() 'Theoretical' 'No action required for ESC5.')
    }

    return $findings
}
