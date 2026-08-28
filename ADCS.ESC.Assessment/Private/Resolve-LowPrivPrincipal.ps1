function Test-EscLowPrivPrincipal {
    <#
    .SYNOPSIS
        Returns $true when a SID represents a broad / low-privileged principal.
    .DESCRIPTION
        Pure function (no external calls). Evaluates a SID string against the set
        of well-known broad principals that should generally NOT hold enrollment,
        write or CA-management rights on AD CS objects:
          - Everyone                S-1-1-0
          - Authenticated Users     S-1-5-11
          - BUILTIN\Users           S-1-5-32-545
          - Domain Users            <domain>-513   (domain-relative RID)
          - Domain Computers        <domain>-515   (domain-relative RID)
        A caller may pass additional SIDs (e.g. a custom broad group discovered in
        the environment) via -ExtraLowPrivSid.
    .PARAMETER Sid
        The SID string to test (e.g. 'S-1-5-21-...-513').
    .PARAMETER ExtraLowPrivSid
        Optional array of extra SID strings to treat as low-privileged.
    .OUTPUTS
        System.Boolean
    .EXAMPLE
        Test-EscLowPrivPrincipal -Sid 'S-1-5-11'   # -> $true
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Sid,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @()
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) {
        return $false
    }

    $normalized = $Sid.Trim().ToUpperInvariant()

    $fixed = @(
        'S-1-1-0',
        'S-1-5-11',
        'S-1-5-32-545'
    )
    if ($fixed -contains $normalized) {
        return $true
    }

    if ($normalized -match '^S-1-5-21-\d+-\d+-\d+-(513|515)$') {
        return $true
    }

    foreach ($extra in $ExtraLowPrivSid) {
        if (-not [string]::IsNullOrWhiteSpace($extra)) {
            if ($extra.Trim().ToUpperInvariant() -eq $normalized) {
                return $true
            }
        }
    }

    return $false
}
