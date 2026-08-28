function Get-EscUnusedPublishedTemplate {
    <#
    .SYNOPSIS
        Lists CA-published templates that have NO still-valid issued certificate
        (read-only, live). Candidates to unpublish and shrink attack surface.
    .DESCRIPTION
        For each Enterprise CA, correlates:
          * the templates published on the CA (Enrollment Service certificateTemplates), and
          * the templates behind currently-valid issued certificates - those whose
            NotAfter is still in the future - read via
            'certutil -view -restrict "Disposition=20,NotAfter>=now" -out CertificateTemplate'.

        A published template with zero active certificates is reported as unused. The
        issued certificate's template identifier (an OID for v2+ templates, a name for
        v1) is resolved back to the template name using the collected template objects
        (Name / DisplayName / Oid). Read-only: certutil -view only READS the CA DB.
    .PARAMETER EnrollmentService
        CA objects from Get-EscEnrollmentService (Name, DnsHostName, PublishedTemplates).
    .PARAMETER Template
        Template objects from Get-EscCertificateTemplate (for OID -> name resolution).
    .OUTPUTS
        [pscustomobject] per CA: CaName, DnsHostName, PublishedCount,
        ActiveTemplateCount, Unused[] (template names), Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [object[]] $EnrollmentService = @(),

        [Parameter(Mandatory = $false)]
        [object[]] $Template = @()
    )

    $byId = @{}
    foreach ($t in $Template) {
        if ($null -eq $t) { continue }
        $nm = [string]$t.Name
        if ([string]::IsNullOrWhiteSpace($nm)) { continue }
        $byId[$nm.ToLowerInvariant()] = $nm
        if ($t.DisplayName) { $byId[([string]$t.DisplayName).ToLowerInvariant()] = $nm }
        if ($t.Oid) { $byId[([string]$t.Oid).ToLowerInvariant()] = $nm }
    }

    $resolve = {
        param($val)
        $v = [string]$val
        if ([string]::IsNullOrWhiteSpace($v)) { return $null }
        $key = $v.Trim().ToLowerInvariant()
        if ($byId.ContainsKey($key)) { return $byId[$key] }
        if ($v -match '^\s*(\S+)\s*\((.+)\)\s*$') {
            $a = $Matches[1].Trim().ToLowerInvariant()
            $b = $Matches[2].Trim().ToLowerInvariant()
            if ($byId.ContainsKey($a)) { return $byId[$a] }
            if ($byId.ContainsKey($b)) { return $byId[$b] }
            return $Matches[2].Trim()
        }
        return $v.Trim()
    }

    $perCa = @()
    foreach ($svc in $EnrollmentService) {
        if ($null -eq $svc) { continue }
        $caName = [string]$svc.Name
        $dns = [string]$svc.DnsHostName
        $published = @($svc.PublishedTemplates | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
        if ($published.Count -eq 0) { continue }

        $short = ($dns -split '\.')[0]
        $isLocalCa = [string]::IsNullOrWhiteSpace($dns) -or ($short -ieq $env:COMPUTERNAME)

        $usedNames = @()
        $err = ''
        try {
            $cuArgs = @()
            if (-not $isLocalCa -and $caName -and $dns) { $cuArgs += @('-config', ('{0}\{1}' -f $dns, $caName)) }
            $cuArgs += @('-view', '-restrict', 'Disposition=20,NotAfter>=now', '-out', 'CertificateTemplate', 'csv')
            $raw = & certutil.exe @cuArgs 2>&1
            $text = ($raw | Out-String)
            if ($LASTEXITCODE -ne 0) { $err = ('certutil -view returned exit {0}.' -f $LASTEXITCODE) }

            $rows = @()
            try { $rows = @($text | ConvertFrom-Csv) } catch { $rows = @() }
            $col = $null
            if ($rows.Count -gt 0) {
                $col = ($rows[0].PSObject.Properties.Name | Where-Object { $_ -match 'Certificate ?Template|Template' } | Select-Object -First 1)
            }
            $set = @{}
            foreach ($row in $rows) {
                $val = ''
                if ($col) { $val = [string]$row.$col }
                else { $val = [string]($row.PSObject.Properties.Value | Select-Object -First 1) }
                $nm = & $resolve $val
                if ($nm) { $set[$nm.ToLowerInvariant()] = $nm }
            }
            $usedNames = @($set.Values)
        }
        catch {
            $err = $_.Exception.Message
        }

        $usedLower = @($usedNames | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $unused = @($published | Where-Object { $usedLower -notcontains ([string]$_).ToLowerInvariant() } | Sort-Object)

        $perCa += [pscustomobject]@{
            CaName              = $caName
            DnsHostName         = $dns
            PublishedCount      = $published.Count
            ActiveTemplateCount = @($usedNames).Count
            Unused              = @($unused)
            Error               = $err
        }
    }

    Write-EscLog -Component 'TemplateUsage' -Message ("Analyzed {0} CA(s) for unused published templates." -f @($perCa).Count)
    return @($perCa)
}
