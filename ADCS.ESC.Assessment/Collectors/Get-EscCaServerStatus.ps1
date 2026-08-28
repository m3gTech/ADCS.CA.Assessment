function Get-EscCaServerStatus {
    <#
    .SYNOPSIS
        Builds a live CA inventory: reachability + certutil ping + Cert Publishers
        cross-check, with discrepancy detection (read-only, live-only).
    .DESCRIPTION
        For every Enterprise CA discovered under the Enrollment Services container
        this correlates three independent sources of truth and flags where they
        disagree:

          1. Enrollment Services (AD configuration) - the CA is registered.
          2. certutil -ping - the CA service actually answers.
          3. Cert Publishers group - the CA computer object is a member.

        Reachability is a passive TCP probe (RPC endpoint mapper, 135) with an ICMP
        fallback. Nothing is enrolled, submitted, or modified. All checks require a
        live domain / Windows tooling; on non-domain or offline runs this is simply
        not invoked.
    .PARAMETER EnrollmentService
        CA objects from Get-EscEnrollmentService (Name, DnsHostName, ...).
    .PARAMETER CertPublisher
        Members from Get-EscCertPublisher (used for the group cross-check).
    .PARAMETER TimeoutMs
        Per-probe TCP connect timeout (default 1500 ms).
    .OUTPUTS
        [pscustomobject] with Servers[], CertPublishers[], Discrepancies[].
    .EXAMPLE
        Get-EscCaServerStatus -EnrollmentService $cas -CertPublisher $pub
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]] $EnrollmentService = @(),

        [Parameter(Mandatory = $false)]
        [object[]] $CertPublisher = @(),

        [Parameter(Mandatory = $false)]
        [int] $TimeoutMs = 1500
    )

    $shortName = {
        param($h)
        if ([string]::IsNullOrWhiteSpace([string]$h)) { return '' }
        return (([string]$h) -split '\.')[0].ToLowerInvariant()
    }

    $cpHosts = @()
    foreach ($cp in $CertPublisher) {
        if ($null -eq $cp) { continue }
        $h = ''
        if ($cp.DnsHostName) { $h = [string]$cp.DnsHostName }
        elseif ($cp.SamAccountName) { $h = ([string]$cp.SamAccountName).TrimEnd('$') }
        elseif ($cp.Name) { $h = [string]$cp.Name }
        if (-not [string]::IsNullOrWhiteSpace($h)) { $cpHosts += $h }
    }
    $cpShort = @($cpHosts | ForEach-Object { & $shortName $_ } | Where-Object { $_ } | Select-Object -Unique)

    $servers = @()
    foreach ($svc in $EnrollmentService) {
        if ($null -eq $svc) { continue }
        $dns = [string]$svc.DnsHostName
        if ([string]::IsNullOrWhiteSpace($dns)) { $dns = [string]$svc.Name }
        $caName = [string]$svc.Name
        $short = & $shortName $dns

        $reachable = $false
        $method = ''
        if (-not [string]::IsNullOrWhiteSpace($dns)) {
            if (Test-EscTcpPort -ComputerName $dns -Port 135 -TimeoutMs $TimeoutMs) {
                $reachable = $true; $method = 'TCP/135'
            }
            else {
                try {
                    if (Test-Connection -ComputerName $dns -Count 1 -Quiet -ErrorAction SilentlyContinue) {
                        $reachable = $true; $method = 'ICMP'
                    }
                }
                catch { }
            }
        }

        $certutilAlive = $null
        $certutilDetail = ''
        if (-not [string]::IsNullOrWhiteSpace($dns) -and -not [string]::IsNullOrWhiteSpace($caName)) {
            $cfg = '{0}\{1}' -f $dns, $caName
            try {
                $raw = & certutil -ping -config $cfg 2>&1
                $text = ($raw | Out-String)
                $exit = $LASTEXITCODE
                $certutilAlive = (($exit -eq 0) -and ($text -match 'interface is alive|completed successfully'))
                $line = @($text -split "`r?`n" | Where-Object { $_ -match 'alive|completed|error|0x8|0x80' } | Select-Object -First 1)
                if ($line.Count -gt 0) { $certutilDetail = ([string]$line[0]).Trim() }
            }
            catch {
                $certutilAlive = $false
                $certutilDetail = $_.Exception.Message
            }
        }

        $inCp = $false
        if ($short) { $inCp = (@($cpShort) -contains $short) }

        $servers += [pscustomobject]@{
            CaName           = $caName
            DnsHostName      = $dns
            Reachable        = $reachable
            ReachableMethod  = $method
            CertutilAlive    = $certutilAlive
            CertutilDetail   = $certutilDetail
            InCertPublishers = $inCp
        }
    }

    $disc = @()
    $esShort = @($servers | ForEach-Object { & $shortName $_.DnsHostName } | Where-Object { $_ } | Select-Object -Unique)

    foreach ($s in $servers) {
        if (-not $s.Reachable) {
            $disc += [pscustomobject]@{
                Type = 'Host unreachable'; Host = $s.DnsHostName
                Detail = 'CA host did not answer TCP/135 or ICMP.'
            }
        }
        if ($s.CertutilAlive -eq $false) {
            $disc += [pscustomobject]@{
                Type = 'CA service down'; Host = $s.DnsHostName
                Detail = ("CA '{0}' does not respond to certutil -ping." -f $s.CaName)
            }
        }
        if (-not $s.InCertPublishers) {
            $disc += [pscustomobject]@{
                Type = 'Missing from Cert Publishers'; Host = $s.DnsHostName
                Detail = 'Enrollment Service CA host is not a member of the Cert Publishers group.'
            }
        }
    }
    foreach ($h in $cpShort) {
        if (@($esShort) -notcontains $h) {
            $disc += [pscustomobject]@{
                Type = 'Orphan Cert Publisher'; Host = $h
                Detail = 'Computer is in Cert Publishers but has no Enrollment Service object (possible stale or rogue CA).'
            }
        }
    }

    Write-EscLog -Component 'CaStatus' -Message ("CA status: {0} server(s), {1} discrepancy(ies)." -f @($servers).Count, @($disc).Count)

    return [pscustomobject]@{
        Servers        = @($servers)
        CertPublishers = @($cpHosts)
        Discrepancies  = @($disc)
    }
}
