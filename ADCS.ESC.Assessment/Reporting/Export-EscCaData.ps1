function Export-EscCaData {
    <#
    .SYNOPSIS
        Exports the CA registry configuration and the issued-certificate list to a
        timestamped folder (read-only; live/Windows only).
    .DESCRIPTION
        Collects two read-only artifacts from a Certification Authority and writes
        them under <OutputRoot>\CA_Assesment_<yyyyMMdd_HHmmss>\ :

          1. The CertSvc Configuration registry subtree
             (HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration,
             confirmed in Microsoft's "Migrate a Certification Authority" guidance).
             * Local target  -> a real importable '.reg' file via 'reg export'.
             * Remote target -> a structured '.json' dump via the remote-registry API,
               plus a 'certutil -config <host\CA> -getreg' text dump.
          2. The issued certificates (Disposition = 20) via 'certutil -view ... csv'.
          3. Published CRLs (base + delta) into a 'CRLs' sub-folder - copied from the
             local CertEnroll folder and/or read from AD CDP objects over LDAP. Never
             publishes a new CRL (no 'certutil -crl').
          4. Optional (-IncludeBackup): a full CA backup into a 'CA_Backup' sub-folder
             (CAName.p12 + Database\) via Backup-CARoleService (certutil -backup fallback).
             With -BackupPassword the private key is included; without it, database only.

        Everything is read-only: reg export, certutil -getreg/-view, the CRL read and the
        backup only READ CA state; no certificate is issued, no CRL is published, no object
        is modified, and the CA service is never stopped. All Windows tooling (reg.exe / certutil.exe / ADCSAdministration)
        is required, so this runs only on a live Windows host. The CA backup additionally
        must run on the CA host itself (local-only).
    .PARAMETER Config
        CA config string 'HostFqdn\CAName'. When given, drives remote certutil calls
        and the ComputerName / CaName defaults.
    .PARAMETER ComputerName
        CA host (defaults to the Config host, else the local machine).
    .PARAMETER CaName
        Sanitized CA name = the sub-key under ...\CertSvc\Configuration (defaults to
        the Config CA, else the local 'Active' value).
    .PARAMETER OutputRoot
        Root folder for the export (default: the current directory). A
        CA_Assesment_<timestamp> sub-folder is created under it. Invoke-ESCAssessment
        passes its report -OutputPath here so reports and exports stay together.
    .PARAMETER IncludeIssued
        Export the issued-certificate list (default: on). Use -IncludeIssued:$false to skip.
    .PARAMETER MaxRows
        Cap the issued-certificate rows written (0 = all, the default).
    .PARAMETER IncludeCrl
        Export published CRLs (base + delta) into a CRLs sub-folder (default: on).
    .PARAMETER IncludeBackup
        Also take a full CA backup (database, plus private key when -BackupPassword is
        given) into a CA_Backup sub-folder. Local-only; off by default.
    .PARAMETER BackupPassword
        SecureString protecting the exported private key (.p12). Omit to back up the
        database only (no private key).
    .OUTPUTS
        [pscustomobject] with FolderPath, Files[], and per-job status.
    .EXAMPLE
        Export-EscCaData
    .EXAMPLE
        Export-EscCaData -Config 'ca01.corp.local\Corp-Issuing-CA' -OutputRoot .\out -IncludeBackup
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Config,

        [Parameter(Mandatory = $false)]
        [string] $ComputerName,

        [Parameter(Mandatory = $false)]
        [string] $CaName,

        [Parameter(Mandatory = $false)]
        [string] $OutputRoot = '.',

        [Parameter(Mandatory = $false)]
        [switch] $IncludeIssued = $true,

        [Parameter(Mandatory = $false)]
        [switch] $IncludeCrl = $true,

        [Parameter(Mandatory = $false)]
        [int] $MaxRows = 0,

        [Parameter(Mandatory = $false)]
        [switch] $IncludeBackup,

        [Parameter(Mandatory = $false)]
        [System.Security.SecureString] $BackupPassword
    )

    $regPath = 'SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    $regFull = 'HKEY_LOCAL_MACHINE\{0}' -f $regPath

    if (-not [string]::IsNullOrWhiteSpace($Config) -and $Config.Contains('\')) {
        $parts = $Config.Split('\', 2)
        if ([string]::IsNullOrWhiteSpace($ComputerName)) { $ComputerName = $parts[0] }
        if ([string]::IsNullOrWhiteSpace($CaName)) { $CaName = $parts[1] }
    }
    if ([string]::IsNullOrWhiteSpace($ComputerName)) { $ComputerName = $env:COMPUTERNAME }

    $localNames = @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')
    try { $localNames += [System.Net.Dns]::GetHostEntry('').HostName } catch { }
    $short = ($ComputerName -split '\.')[0]
    $isLocal = [string]::IsNullOrWhiteSpace($ComputerName) -or ($localNames -contains $ComputerName) -or `
               ($localNames -contains $short) -or ($short -eq $env:COMPUTERNAME)

    $ts = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $folder = Join-Path -Path $OutputRoot -ChildPath ('CA_Assesment_{0}' -f $ts)
    try {
        if (-not (Test-Path -LiteralPath $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    }
    catch {
        Write-EscLog -Component 'CaExport' -Level Warning -Message ("Cannot create output folder '{0}': {1}" -f $folder, $_.Exception.Message)
        return [pscustomobject]@{ FolderPath = $folder; Files = @(); Jobs = @(); Error = $_.Exception.Message }
    }

    $files = New-Object System.Collections.Generic.List[string]
    $jobs = New-Object System.Collections.Generic.List[object]
    $record = {
        param($Name, $Path, $Ok, $Detail, $Acl = $null)
        $jobs.Add([pscustomobject]@{ Job = $Name; Path = $Path; Success = [bool]$Ok; Detail = [string]$Detail; AclHardened = $Acl })
        if ($Ok -and $Path -and (Test-Path -LiteralPath $Path)) { $files.Add([string]$Path) }
    }

    if ($isLocal) {
        $regFile = Join-Path $folder ('CertSvc_Configuration_{0}.reg' -f $ts)
        try {
            $out = & reg.exe export $regFull $regFile /y 2>&1
            $ok = ($LASTEXITCODE -eq 0) -and (Test-Path -LiteralPath $regFile)
            & $record 'CertSvc_Configuration (reg export)' $regFile $ok (($out | Out-String).Trim())
        }
        catch {
            & $record 'CertSvc_Configuration (reg export)' $regFile $false $_.Exception.Message
        }
    }
    else {
        $jsonFile = Join-Path $folder ('CertSvc_Configuration_{0}.json' -f $ts)
        try {
            $dump = ConvertTo-EscRegistryDump -ComputerName $ComputerName -SubKey $regPath
            ($dump | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $jsonFile -Encoding UTF8
            & $record 'CertSvc_Configuration (remote registry json)' $jsonFile $true ''
        }
        catch {
            & $record 'CertSvc_Configuration (remote registry json)' $jsonFile $false $_.Exception.Message
        }
    }

    $getregFile = Join-Path $folder ('CA_Registry_getreg_{0}.txt' -f $ts)
    try {
        if ($isLocal) { $raw = & certutil.exe -getreg 2>&1 }
        else { $raw = & certutil.exe -config $Config -getreg 2>&1 }
        ($raw | Out-String) | Set-Content -LiteralPath $getregFile -Encoding UTF8
        & $record 'CA_Registry_getreg (certutil)' $getregFile ($LASTEXITCODE -eq 0) ''
    }
    catch {
        & $record 'CA_Registry_getreg (certutil)' $getregFile $false $_.Exception.Message
    }

    if ($IncludeIssued) {
        $csvFile = Join-Path $folder ('Issued_Certificates_{0}.csv' -f $ts)
        $cols = 'RequestID,Request.RequesterName,CommonName,CertificateTemplate,SerialNumber,NotBefore,NotAfter,CertificateHash'
        try {
            $cuArgs = @()
            if (-not $isLocal -and -not [string]::IsNullOrWhiteSpace($Config)) { $cuArgs += @('-config', $Config) }
            $cuArgs += @('-view', '-restrict', 'Disposition=20', '-out', $cols, 'csv')
            $raw = & certutil.exe @cuArgs 2>&1
            $text = ($raw | Out-String)
            if ($MaxRows -gt 0) {
                $lines = @($text -split "`r?`n")
                if ($lines.Count -gt ($MaxRows + 1)) { $text = ($lines[0..$MaxRows] -join "`r`n") }
            }
            $text | Set-Content -LiteralPath $csvFile -Encoding UTF8
            & $record 'Issued_Certificates (certutil -view)' $csvFile ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $csvFile)) ''
        }
        catch {
            & $record 'Issued_Certificates (certutil -view)' $csvFile $false $_.Exception.Message
        }
    }

    if ($IncludeCrl) {
        $crlDir = Join-Path $folder 'CRLs'
        try {
            $crl = Export-EscCrlList -CrlDir $crlDir -IsLocal $isLocal -CaName $CaName
            & $record 'CRL_Lists' $crlDir ($crl.Count -gt 0) $crl.Detail
        }
        catch {
            & $record 'CRL_Lists' $crlDir $false $_.Exception.Message
        }
    }

    if ($IncludeBackup) {
        $backupDir = Join-Path $folder 'CA_Backup'
        if (-not $isLocal) {
            & $record 'CA_Backup' $null $false 'CA backup is local-only; run this on the CA host.'
        }
        else {
            try {
                if (-not (Test-Path -LiteralPath $backupDir)) { New-Item -ItemType Directory -Path $backupDir -Force | Out-Null }
                $hasCmd = $null -ne (Get-Command -Name 'Backup-CARoleService' -ErrorAction SilentlyContinue)
                if ($hasCmd) {
                    if ($null -ne $BackupPassword) {
                        Backup-CARoleService -Path $backupDir -Password $BackupPassword -ErrorAction Stop
                        $detail = 'Full backup via Backup-CARoleService (database + private key).'
                    }
                    else {
                        Backup-CARoleService -Path $backupDir -DatabaseOnly -ErrorAction Stop
                        $detail = 'Database-only backup (no -BackupPassword supplied; private key NOT included).'
                    }
                }
                else {
                    if ($null -ne $BackupPassword) {
                        $plain = (New-Object System.Net.NetworkCredential('', $BackupPassword)).Password
                        $out = & certutil.exe -f -p $plain -backup $backupDir 2>&1
                        $plain = $null
                        $detail = 'Full backup via certutil (database + private key).'
                    }
                    else {
                        $out = & certutil.exe -f -backupdb $backupDir 2>&1
                        $detail = 'Database-only backup via certutil (no password; private key NOT included).'
                    }
                }
                $hasFiles = @(Get-ChildItem -LiteralPath $backupDir -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0

                $aclOk = $false
                if ($hasFiles) {
                    $aclOk = Protect-EscBackupFolder -Path $backupDir
                    if ($aclOk) { $detail += ' ACL hardened to Administrators/SYSTEM only.' }
                    else { $detail += ' WARNING: ACL hardening failed - secure this folder manually.' }
                }
                & $record 'CA_Backup' $backupDir $hasFiles $detail $aclOk
            }
            catch {
                & $record 'CA_Backup' $backupDir $false $_.Exception.Message
            }
        }
    }

    $fileCount = $files.Count
    $jobCount = $jobs.Count
    Write-EscLog -Component 'CaExport' -Message ("CA export -> {0} ({1} file(s), {2} job(s))." -f $folder, $fileCount, $jobCount)

    return [pscustomobject]@{
        FolderPath   = $folder
        ComputerName = $ComputerName
        CaName       = $CaName
        IsLocal      = $isLocal
        Files        = $files.ToArray()
        Jobs         = $jobs.ToArray()
    }
}
