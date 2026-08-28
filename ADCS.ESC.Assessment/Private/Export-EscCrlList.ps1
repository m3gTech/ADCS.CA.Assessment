function Export-EscCrlList {
    <#
    .SYNOPSIS
        Gathers published CRLs (base + delta) into a folder, read-only.
    .DESCRIPTION
        Collects existing Certificate Revocation Lists without ever publishing a new
        one (it never runs 'certutil -crl', which would change CA state). Two sources:

          1. Local CertEnroll folder (%SystemRoot%\System32\CertSrv\CertEnroll\*.crl)
             when running on the CA host.
          2. AD-published CRLs read over LDAP from the CDP objects under
             CN=CDP,CN=Public Key Services,CN=Services,<configNC> - the
             certificateRevocationList / deltaRevocationList attributes. This works
             from any domain-joined host (serverless bind).

        Files are written as <cn>.crl (base) and <cn>+.crl (delta). Never throws.
    .PARAMETER CrlDir
        Destination folder (created if missing).
    .PARAMETER IsLocal
        When $true, also copy the local CertEnroll *.crl files.
    .PARAMETER Server
        Optional DC to bind for the AD read (default: serverless / current domain).
    .PARAMETER CaName
        Optional CA sanitized name to restrict the AD CDP objects to that CA.
    .OUTPUTS
        [pscustomobject] with Count and Detail.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $CrlDir,

        [Parameter(Mandatory = $false)]
        [bool] $IsLocal = $true,

        [Parameter(Mandatory = $false)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $CaName
    )

    if (-not (Test-Path -LiteralPath $CrlDir)) { New-Item -ItemType Directory -Path $CrlDir -Force | Out-Null }
    $count = 0
    $notes = @()

    if ($IsLocal) {
        try {
            $certEnroll = Join-Path $env:SystemRoot 'System32\CertSrv\CertEnroll'
            if (Test-Path -LiteralPath $certEnroll) {
                $localCrls = @(Get-ChildItem -LiteralPath $certEnroll -Filter '*.crl' -File -ErrorAction SilentlyContinue)
                foreach ($file in $localCrls) {
                    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $CrlDir $file.Name) -Force -ErrorAction SilentlyContinue
                    $count++
                }
                if ($localCrls.Count -gt 0) { $notes += ('CertEnroll: {0} file(s).' -f $localCrls.Count) }
            }
        }
        catch {
            $notes += ('CertEnroll error: {0}' -f $_.Exception.Message)
        }
    }

    try {
        $configNc = Get-EscConfigNamingContext -Server $Server
        if (-not [string]::IsNullOrWhiteSpace($configNc)) {
            $cdpRoot = 'CN=CDP,CN=Public Key Services,CN=Services,{0}' -f $configNc
            $filter = '(objectClass=cRLDistributionPoint)'
            if (-not [string]::IsNullOrWhiteSpace($CaName)) {
                $esc = $CaName -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29' -replace '\*', '\2a'
                $filter = '(&(objectClass=cRLDistributionPoint)(cn={0}))' -f $esc
            }
            $res = @(Invoke-EscLdapSearch -SearchRoot $cdpRoot -Filter $filter -Server $Server `
                -PropertiesToLoad @('cn', 'certificateRevocationList', 'deltaRevocationList') -SearchScope 'Subtree')
            $adCount = 0
            foreach ($r in $res) {
                $bag = ConvertTo-EscPropertyBag -SearchResult $r
                $cn = 'crl'
                if ($bag.ContainsKey('cn') -and @($bag['cn']).Count -gt 0) { $cn = [string]$bag['cn'][0] }
                $safe = ($cn -replace '[\\/:*?"<>|]', '_')

                if ($bag.ContainsKey('certificaterevocationlist') -and @($bag['certificaterevocationlist']).Count -gt 0) {
                    $b = $bag['certificaterevocationlist'][0]
                    if ($b -is [byte[]]) {
                        [System.IO.File]::WriteAllBytes((Join-Path $CrlDir ($safe + '.crl')), [byte[]]$b)
                        $count++; $adCount++
                    }
                }
                if ($bag.ContainsKey('deltarevocationlist') -and @($bag['deltarevocationlist']).Count -gt 0) {
                    $d = $bag['deltarevocationlist'][0]
                    if ($d -is [byte[]]) {
                        [System.IO.File]::WriteAllBytes((Join-Path $CrlDir ($safe + '+.crl')), [byte[]]$d)
                        $count++; $adCount++
                    }
                }
            }
            if ($adCount -gt 0) { $notes += ('AD CDP: {0} CRL(s).' -f $adCount) }
        }
    }
    catch {
        $notes += ('AD CDP error: {0}' -f $_.Exception.Message)
    }

    if ($notes.Count -eq 0) { $notes += 'No CRLs found (CertEnroll empty and none published to AD).' }
    return [pscustomobject]@{ Count = $count; Detail = ($notes -join ' ') }
}
