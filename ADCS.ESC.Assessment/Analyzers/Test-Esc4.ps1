function Test-Esc4 {
    <#
    .SYNOPSIS
        ESC4 - Certificate template with a dangerous (writable) DACL.
    .DESCRIPTION
        Flags certificate templates on which a low-privileged principal holds a
        write-class right (WriteDacl / WriteOwner / WriteProperty / GenericWrite /
        GenericAll). Such a principal can reconfigure the template (e.g. add
        enrollee-supplied SAN, add a client-auth EKU, grant themselves Enroll),
        turning any template into an ESC1-style escalation.

        Vulnerable (per template) = any Ace in WritePrincipals with
          AceType == Allow AND IsLowPriv == $true AND Rights intersects
          {WriteDacl, WriteOwner, WriteProperty, GenericWrite, GenericAll};
        OR the template owner is a low-priv principal (when owner SID is available).
    .PARAMETER Context
        AssessmentContext pscustomobject. Reads $Context.Templates.
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

    $reference = 'SpecterOps "Certified Pre-Owned" (ESC4) / Certipy'
    $writeRights = @('WriteDacl', 'WriteOwner', 'WriteProperty', 'GenericWrite', 'GenericAll')
    $findings = @()

    $newFinding = {
        param($Title, $Severity, $Status, $Affected, $Evidence, $Principals, $Exploit, $Remediation)
        [pscustomobject]@{
            Id             = 'ESC4'
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

    $templates = @()
    if ($null -ne $Context -and $null -ne $Context.Templates) { $templates = @($Context.Templates) }

    if ($templates.Count -eq 0) {
        return @(& $newFinding 'ESC4 - no certificate templates available' 'Critical' 'ManualReview' 'N/A' `
            ([pscustomobject]@{ Error = 'Context.Templates is empty or unavailable; could not evaluate ESC4.' }) `
            @() 'Theoretical' 'Collect certificate templates and re-run the assessment.')
    }

    $extra = @()
    if ($ExtraLowPrivSid) { $extra += $ExtraLowPrivSid }
    if ($null -ne $Context.ExtraLowPrivSid) { $extra += $Context.ExtraLowPrivSid }

    foreach ($tpl in $templates) {
        $badAces = @($tpl.WritePrincipals | Where-Object {
            $_.AceType -eq 'Allow' -and $_.IsLowPriv -and (@($_.Rights | Where-Object { $writeRights -contains $_ }).Count -gt 0)
        })

        $ownerSid = $null
        if ($null -ne $tpl.Raw -and $tpl.Raw.PSObject.Properties['OwnerSid']) { $ownerSid = $tpl.Raw.OwnerSid }
        $ownerLowPriv = $false
        if ($ownerSid) { $ownerLowPriv = Test-EscLowPrivPrincipal -Sid $ownerSid -ExtraLowPrivSid $extra }

        if ($badAces.Count -eq 0 -and -not $ownerLowPriv) { continue }

        $principalNames = @()
        $principalNames += @($badAces | ForEach-Object { if ($_.PrincipalName) { $_.PrincipalName } else { $_.PrincipalSid } })
        if ($ownerLowPriv) { $principalNames += ('OWNER:{0}' -f $ownerSid) }
        $principalNames = @($principalNames | Select-Object -Unique)

        $evidence = [pscustomobject]@{
            DangerousAces = @($badAces | ForEach-Object {
                [pscustomobject]@{
                    Principal   = $_.PrincipalName
                    Sid         = $_.PrincipalSid
                    Rights      = @($_.Rights)
                    AccessMask  = ('0x{0:X}' -f [int]$_.AccessMask)
                }
            })
            OwnerSid          = $ownerSid
            OwnerIsLowPriv    = $ownerLowPriv
            WriteRightsTested = $writeRights
        }

        $findings += & $newFinding `
            ("ESC4 - template '{0}' has a low-priv-writable DACL" -f $tpl.Name) `
            'Critical' 'Vulnerable' $tpl.Name $evidence $principalNames 'High' `
            'Remove write/owner rights from low-privileged principals on the template object; restrict the DACL to trusted administrative groups.'
    }

    if ($findings.Count -eq 0) {
        return @(& $newFinding 'ESC4 - no templates with low-priv-writable DACLs' 'Critical' 'NotVulnerable' 'N/A' `
            ([pscustomobject]@{ TemplatesEvaluated = $templates.Count }) @() 'Theoretical' 'No action required for ESC4.')
    }

    return $findings
}
