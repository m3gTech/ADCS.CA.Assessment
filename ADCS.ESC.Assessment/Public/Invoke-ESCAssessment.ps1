function Invoke-ESCAssessment {
    <#
    .SYNOPSIS
        Read-only AD CS ESC1-ESC16 security assessment. Non-destructive.
    .DESCRIPTION
        Orchestrates the assessment:
          1. Collects AD CS configuration (read-only) via the Get-Esc* collectors,
             or loads normalized fixtures in offline mode.
          2. Cross-references published templates onto CAs (Template.PublishedOnCAs).
          3. Builds a single AssessmentContext and runs every Test-Esc1..16 analyzer.
          4. Scores findings (Get-EscRiskScore) and computes the overall posture
             (Get-EscPostureScore).
          5. Exports an HTML (scored, visual) and/or JSON report.

        ABSOLUTELY read-only: no certificate is ever requested/issued and no AD/CA
        object is modified. Enrollment rights are computed from ACLs, never exercised.

    .PARAMETER Server
        Optional DC/server to target for live collection.
    .PARAMETER OutputPath
        Directory to write reports into (created if missing). Defaults to the current
        directory. Files: esc-assessment-report.html / .json.
    .PARAMETER Format
        One or more of 'Html','Json' (default both).
    .PARAMETER Offline
        Load normalized fixtures from -FixturePath instead of live collection.
    .PARAMETER FixturePath
        Directory of normalized fixture JSON files (used with -Offline):
          templates.json, enrollmentservices.json, caconfigs.json, pkiacls.json,
          dcmappings.json, webendpoints.json, oidgrouplinks.json,
          altsecurityidentities.json  (any missing file is treated as empty).
    .PARAMETER ExtraLowPrivSid
        Extra SIDs to treat as low-privileged (e.g., a broad custom group).
    .PARAMETER CollectOnly
        Only run collection and return the AssessmentContext (no analysis/report).
    .PARAMETER ExportCaData
        Also export each CA's registry + issued certificates (live-only) into a
        CA_Assesment_<timestamp> folder under the report output directory, so reports
        and exports sit together in one place.
    .PARAMETER CaExportRoot
        Override the export root. Defaults to -OutputPath when omitted.
    .PARAMETER BackupCa
        With -ExportCaData, also take a CA backup (local CA only) into the same folder.
    .PARAMETER CaBackupPassword
        SecureString protecting the exported CA private key (.p12); omit for a
        database-only backup.
    .PARAMETER AnalyzeTemplateUsage
        Live-only. Analyze which CA-published templates have no still-valid issued
        certificate (runs certutil -view per CA; off by default as it can be slow on
        large CA databases).
    .OUTPUTS
        [pscustomobject] with Summary, Findings, Context, ReportPaths, and (live only)
        CaStatus, CaExports, and UnusedTemplates.
    .EXAMPLE
        Invoke-ESCAssessment -OutputPath .\out
    .EXAMPLE
        Invoke-ESCAssessment -Offline -FixturePath .\tests\fixtures\sample -OutputPath .\out
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $OutputPath = '.',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Html', 'Json')]
        [string[]] $Format = @('Html', 'Json'),

        [Parameter(Mandatory = $false)]
        [switch] $Offline,

        [Parameter(Mandatory = $false)]
        [string] $FixturePath,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @(),

        [Parameter(Mandatory = $false)]
        [switch] $CollectOnly,

        [Parameter(Mandatory = $false)]
        [switch] $ExportCaData,

        [Parameter(Mandatory = $false)]
        [string] $CaExportRoot,

        [Parameter(Mandatory = $false)]
        [switch] $BackupCa,

        [Parameter(Mandatory = $false)]
        [System.Security.SecureString] $CaBackupPassword,

        [Parameter(Mandatory = $false)]
        [switch] $AnalyzeTemplateUsage
    )

    $stamp = (Get-Date).ToString('o')
    Write-EscLog -Component 'Orchestrator' -Message 'Starting AD CS ESC assessment (read-only).'

    $templates = @(); $enrollSvc = @(); $caConfigs = @(); $pkiAcls = @()
    $dcMaps = @(); $webEps = @(); $oidLinks = @(); $altSecIds = @()
    $mode = 'Live'
    $caStatus = $null
    $caExports = @()
    $unusedTemplates = @()

    if ($Offline) {
        $mode = 'Offline'
        if ([string]::IsNullOrWhiteSpace($FixturePath) -or -not (Test-Path -LiteralPath $FixturePath)) {
            throw "Offline mode requires an existing -FixturePath. Got: '$FixturePath'"
        }
        $loadFx = {
            param($File)
            $p = Join-Path -Path $FixturePath -ChildPath $File
            if (Test-Path -LiteralPath $p) {
                $raw = Get-Content -LiteralPath $p -Raw
                if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
                return @($raw | ConvertFrom-Json)
            }
            return @()
        }
        $templates = @(& $loadFx 'templates.json')
        $enrollSvc = @(& $loadFx 'enrollmentservices.json')
        $caConfigs = @(& $loadFx 'caconfigs.json')
        $pkiAcls   = @(& $loadFx 'pkiacls.json')
        $dcMaps    = @(& $loadFx 'dcmappings.json')
        $webEps    = @(& $loadFx 'webendpoints.json')
        $oidLinks  = @(& $loadFx 'oidgrouplinks.json')
        $altSecIds = @(& $loadFx 'altsecurityidentities.json')
        Write-EscLog -Component 'Orchestrator' -Message ("Offline fixtures loaded: {0} templates, {1} CAs, {2} DCs." -f $templates.Count, $caConfigs.Count, $dcMaps.Count)
    }
    else {
        $templates = @(Get-EscCertificateTemplate -Server $Server -ExtraLowPrivSid $ExtraLowPrivSid)
        $enrollSvc = @(Get-EscEnrollmentService -Server $Server)
        $caConfigs = @(Get-EscCaConfiguration -CA $enrollSvc -ExtraLowPrivSid $ExtraLowPrivSid -ErrorAction SilentlyContinue)
        $pkiAcls   = @(Get-EscPkiObjectAcl -Server $Server -ExtraLowPrivSid $ExtraLowPrivSid)
        $dcMaps    = @(Get-EscDomainMapping -ErrorAction SilentlyContinue)
        $webEps    = @(Get-EscWebEnrollmentEndpoint -CA $enrollSvc -ErrorAction SilentlyContinue)
        $oidLinks  = @(Get-EscOidGroupLink -Server $Server)
        $altSecIds = @(Get-EscAltSecurityIdentity -Server $Server -ExtraLowPrivSid $ExtraLowPrivSid)

        $certPublishers = @()
        try { $certPublishers = @(Get-EscCertPublisher -Server $Server) }
        catch { Write-EscLog -Component 'Orchestrator' -Level Warning -Message ("Cert Publishers read failed: {0}" -f $_.Exception.Message) }
        try { $caStatus = Get-EscCaServerStatus -EnrollmentService $enrollSvc -CertPublisher $certPublishers }
        catch { Write-EscLog -Component 'Orchestrator' -Level Warning -Message ("CA status collection failed: {0}" -f $_.Exception.Message) }

        if ($ExportCaData) {
            $exportRoot = $OutputPath
            if (-not [string]::IsNullOrWhiteSpace($CaExportRoot)) { $exportRoot = $CaExportRoot }
            if (@($enrollSvc).Count -gt 0) {
                # De-duplicate enrollment-service records so each CA (host\CAName) is
                # exported once. AD can return stale/partial pKIEnrollmentService
                # objects for the same physical CA; exporting per raw record produced
                # a duplicate (and a failing) card for one CA. Records that cannot be
                # resolved to a concrete host\CAName target are skipped here.
                $seenCa = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($svc in $enrollSvc) {
                    $cfg = $null
                    if ($svc.DnsHostName -and $svc.Name) { $cfg = '{0}\{1}' -f $svc.DnsHostName, $svc.Name }
                    if ([string]::IsNullOrWhiteSpace($cfg)) { continue }
                    if (-not $seenCa.Add($cfg)) { continue }
                    $caExports += Export-EscCaData -Config $cfg -OutputRoot $exportRoot -IncludeBackup:$BackupCa -BackupPassword $CaBackupPassword
                }
                # If no record resolved to a concrete target, fall back to a single
                # local export so a lone on-box CA is still captured.
                if ($seenCa.Count -eq 0) {
                    $caExports += Export-EscCaData -OutputRoot $exportRoot -IncludeBackup:$BackupCa -BackupPassword $CaBackupPassword
                }
            }
            else {
                $caExports += Export-EscCaData -OutputRoot $exportRoot -IncludeBackup:$BackupCa -BackupPassword $CaBackupPassword
            }
        }

        if ($AnalyzeTemplateUsage) {
            try {
                $unusedTemplates = @(Get-EscUnusedPublishedTemplate -EnrollmentService $enrollSvc -Template $templates)
            }
            catch {
                Write-EscLog -Component 'Orchestrator' -Level Warning -Message ("Unused-template analysis failed: {0}" -f $_.Exception.Message)
            }
        }
    }

    if (@($enrollSvc).Count -gt 0) {
        foreach ($tpl in $templates) {
            if ($null -eq $tpl) { continue }
            $pub = @()
            foreach ($svc in $enrollSvc) {
                $names = @($svc.PublishedTemplates)
                if ($names -contains $tpl.Name) { $pub += $svc.Name }
            }
            if ($tpl.PSObject.Properties.Name -contains 'PublishedOnCAs') {
                $tpl.PublishedOnCAs = @($pub)
            }
            else {
                Add-Member -InputObject $tpl -NotePropertyName 'PublishedOnCAs' -NotePropertyValue @($pub) -Force
            }
        }
    }

    $context = [pscustomobject]@{
        Templates             = @($templates)
        EnrollmentServices    = @($enrollSvc)
        CaConfigs             = @($caConfigs)
        PkiAcls               = @($pkiAcls)
        DcMappings            = @($dcMaps)
        WebEndpoints          = @($webEps)
        OidGroupLinks         = @($oidLinks)
        AltSecurityIdentities = @($altSecIds)
        ExtraLowPrivSid       = @($ExtraLowPrivSid)
        Meta                  = @{ GeneratedAt = $stamp; Mode = $mode; Server = $Server }
    }

    if ($CollectOnly) {
        Write-EscLog -Component 'Orchestrator' -Message 'CollectOnly set; returning context without analysis.'
        return [pscustomobject]@{ Summary = $null; Findings = @(); Context = $context; ReportPaths = @() }
    }

    $analyzers = 1..16 | ForEach-Object { "Test-Esc$_" }
    $findings = @()
    foreach ($fn in $analyzers) {
        $cmd = Get-Command -Name $fn -ErrorAction SilentlyContinue
        if ($null -eq $cmd) {
            Write-EscLog -Component 'Orchestrator' -Level Warning -Message "Analyzer '$fn' not found; skipping."
            continue
        }
        try {
            $res = & $fn -Context $context -ExtraLowPrivSid $ExtraLowPrivSid
            if ($null -ne $res) { $findings += @($res) }
        }
        catch {
            Write-EscLog -Component 'Orchestrator' -Level Warning -Message ("Analyzer '{0}' threw: {1}" -f $fn, $_.Exception.Message)
            $findings += [pscustomobject]@{
                Id = ($fn -replace 'Test-Esc', 'ESC'); Title = "$fn failed to run"; Severity = 'Info'
                Status = 'Error'; AffectedObject = 'N/A'
                Evidence = [pscustomobject]@{ Error = $_.Exception.Message }
                Principals = @(); Exploitability = 'Theoretical'; RiskScore = 0
                Remediation = 'Investigate analyzer error / data availability.'; Reference = ''
            }
        }
    }

    $findings = @($findings | Get-EscRiskScore)
    $summary = Get-EscPostureScore -Finding $findings

    Write-EscLog -Component 'Orchestrator' -Message ("Assessment complete. Posture {0} ({1}); {2} finding(s)." -f $summary.PostureScore, $summary.Grade, @($findings).Count)

    $reportPaths = @()
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $meta = @{ GeneratedAt = $stamp; Mode = $mode; Server = $Server; Tool = 'ADCS.ESC.Assessment' }
    if ($null -ne $caStatus) { $meta['CaStatus'] = $caStatus }
    if (@($caExports).Count -gt 0) { $meta['CaExports'] = @($caExports) }
    if (@($unusedTemplates).Count -gt 0) { $meta['UnusedTemplates'] = @($unusedTemplates) }

    # CA management-role inventory: who holds Manage CA / Issue and Manage
    # Certificates, with non-default (outside Administrators / Domain Admins /
    # Enterprise Admins) assignments flagged for review.
    $caRoleAssignments = @(Get-EscCaRoleAssignment -CaConfig $caConfigs)
    if (@($caRoleAssignments | Where-Object { $_.AcesAvailable }).Count -gt 0) {
        $meta['CaRoleAssignments'] = @($caRoleAssignments)
    }

    if ($Format -contains 'Json') {
        $jsonPath = Join-Path -Path $OutputPath -ChildPath 'esc-assessment-report.json'
        $reportPaths += (Export-EscJsonReport -Finding $findings -Summary $summary -Meta $meta -Path $jsonPath)
    }
    if ($Format -contains 'Html') {
        $htmlPath = Join-Path -Path $OutputPath -ChildPath 'esc-assessment-report.html'
        $reportPaths += (Export-EscHtmlReport -Finding $findings -Summary $summary -Meta $meta -Path $htmlPath)
    }

    return [pscustomobject]@{
        Summary     = $summary
        Findings    = @($findings)
        Context     = $context
        CaStatus    = $caStatus
        CaExports   = @($caExports)
        UnusedTemplates = @($unusedTemplates)
        CaRoleAssignments = @($caRoleAssignments)
        ReportPaths = @($reportPaths)
    }
}
