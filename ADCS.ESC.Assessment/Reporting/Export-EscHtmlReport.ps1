function Export-EscHtmlReport {
<#
.SYNOPSIS
    Renders an AD CS security-assessment result set as a self-contained HTML report.

.DESCRIPTION
    Read-only, non-destructive reporter. Produces a single polished HTML file with all
    CSS and JS inlined (no external CDN / network / images / fonts), so it renders fully
    offline in an isolated environment.

    The report includes:
      * Executive header: Posture Score (0-100) + letter Grade (A green -> F red),
        Domain/Forest/GeneratedAt from Meta, and a Critical/High/Medium/Low severity strip.
      * Summary section: pure-CSS bar charts of findings by severity and by status.
      * Per-finding cards grouped by ESC Id (groups ordered by highest RiskScore desc,
        findings within a group sorted by RiskScore desc): severity badge, status badge,
        Id + Title, AffectedObject, RiskScore, Principals, an Evidence key/value table
        (nested objects/arrays handled gracefully), Remediation, and a Reference link.
      * A read-only / non-destructive disclaimer and ethical-use footer.

    All dynamic text is HTML-encoded through an internal Encode helper to prevent layout
    breakage or injection from object names.

    Tolerant by design: if -Summary is $null a minimal summary is computed from the
    findings; any missing field renders as "-" instead of throwing.

.PARAMETER Finding
    Zero or more Finding [pscustomobject] items.

.PARAMETER Summary
    Optional summary object (Get-EscPostureScore shape: PostureScore, Grade, counts,
    BySeverity, ByStatus, TopFindings). If omitted, a minimal summary is derived.

.PARAMETER Meta
    Optional hashtable of run metadata (Domain, Forest, GeneratedAt, Mode, Tool, ...).

.PARAMETER Path
    Destination file path for the HTML document.

.OUTPUTS
    [string] The path that was written.

.EXAMPLE
    Export-EscHtmlReport -Finding $findings -Summary $summary -Meta @{Domain='corp.local'} -Path .\report.html
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [pscustomobject[]] $Finding,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [pscustomobject] $Summary,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable] $Meta,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    if ($null -eq $Finding) { $Finding = @() }

    $logoDataUri = ''
    try {
        $logoPath = Join-Path -Path $PSScriptRoot -ChildPath '..\..\assets\logo.png'
        if (Test-Path -LiteralPath $logoPath) {
            $logoBytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $logoPath).Path)
            $logoDataUri = 'data:image/png;base64,' + [System.Convert]::ToBase64String($logoBytes)
        }
    } catch { $logoDataUri = '' }

    function Encode {
        param([object] $Text)
        if ($null -eq $Text) { return '' }
        $s = [string]$Text
        $s = $s.Replace('&', '&amp;')
        $s = $s.Replace('<', '&lt;')
        $s = $s.Replace('>', '&gt;')
        $s = $s.Replace('"', '&quot;')
        $s = $s.Replace("'", '&#39;')
        return $s
    }

    function Get-Prop {
        param([object] $Object, [string] $Name)
        if ($null -eq $Object) { return $null }
        $p = $Object.PSObject.Properties[$Name]
        if ($null -eq $p) { return $null }
        return $p.Value
    }

    function Show {
        param([object] $Value)
        if ($null -eq $Value) { return '-' }
        $s = [string]$Value
        if ([string]::IsNullOrWhiteSpace($s)) { return '-' }
        return $s
    }

    function Get-SevClass {
        param([string] $Severity)
        switch ("$Severity".ToLower()) {
            'critical' { return 'critical' }
            'high'     { return 'high' }
            'medium'   { return 'medium' }
            'low'      { return 'low' }
            'info'     { return 'info' }
            default    { return 'info' }
        }
    }

    function Get-StatusClass {
        param([string] $Status)
        switch ("$Status".ToLower()) {
            'vulnerable'    { return 'st-vuln' }
            'potential'     { return 'st-pot' }
            'manualreview'  { return 'st-manual' }
            'notvulnerable' { return 'st-ok' }
            'error'         { return 'st-err' }
            default         { return 'st-unknown' }
        }
    }

    function Get-GradeClass {
        param([string] $Grade)
        switch ("$Grade".ToUpper()) {
            'A' { return 'grade-a' }
            'B' { return 'grade-b' }
            'C' { return 'grade-c' }
            'D' { return 'grade-d' }
            'F' { return 'grade-f' }
            default { return 'grade-na' }
        }
    }

    function Render-Evidence {
        param([object] $Value, [int] $Depth = 0)

        if ($Depth -gt 6) { return (Encode ([string]$Value)) }
        if ($null -eq $Value) { return '<span class="muted">-</span>' }

        if ($Value -is [string] -or $Value -is [ValueType]) {
            return (Encode ([string]$Value))
        }

        if ($Value -is [System.Collections.IDictionary]) {
            $rows = ''
            foreach ($k in $Value.Keys) {
                $rows += '<tr><th>' + (Encode ([string]$k)) + '</th><td>' +
                         (Render-Evidence -Value $Value[$k] -Depth ($Depth + 1)) + '</td></tr>'
            }
            if ($rows -eq '') { return '<span class="muted">-</span>' }
            return '<table class="kv">' + $rows + '</table>'
        }

        if ($Value -is [System.Collections.IEnumerable]) {
            $items = @($Value)
            if ($items.Count -eq 0) { return '<span class="muted">(empty)</span>' }
            $allScalar = $true
            foreach ($it in $items) {
                if ($null -ne $it -and -not ($it -is [string]) -and -not ($it -is [ValueType])) {
                    $allScalar = $false; break
                }
            }
            if ($allScalar) {
                $parts = @()
                foreach ($it in $items) { $parts += (Encode ([string]$it)) }
                return ($parts -join '<span class="sep">, </span>')
            }
            $lis = ''
            foreach ($it in $items) {
                $lis += '<li>' + (Render-Evidence -Value $it -Depth ($Depth + 1)) + '</li>'
            }
            return '<ul class="ev-list">' + $lis + '</ul>'
        }

        if ($Value -is [pscustomobject] -or $Value.PSObject.Properties.Count -gt 0) {
            $rows = ''
            foreach ($p in $Value.PSObject.Properties) {
                $rows += '<tr><th>' + (Encode ([string]$p.Name)) + '</th><td>' +
                         (Render-Evidence -Value $p.Value -Depth ($Depth + 1)) + '</td></tr>'
            }
            if ($rows -eq '') { return (Encode ([string]$Value)) }
            return '<table class="kv">' + $rows + '</table>'
        }

        return (Encode ([string]$Value))
    }

    $sevOrder = @('Critical', 'High', 'Medium', 'Low', 'Info')
    $statusOrder = @('Vulnerable', 'Potential', 'ManualReview', 'NotVulnerable', 'Error')

    $sevCounts = [ordered]@{}
    foreach ($s in $sevOrder) { $sevCounts[$s] = 0 }
    $statusCounts = [ordered]@{}
    foreach ($s in $statusOrder) { $statusCounts[$s] = 0 }

    foreach ($f in $Finding) {
        if ($null -eq $f) { continue }
        $sev = [string](Get-Prop $f 'Severity')
        if ([string]::IsNullOrEmpty($sev)) { $sev = 'Info' }
        if (-not $sevCounts.Contains($sev)) { $sevCounts[$sev] = 0 }
        $sevCounts[$sev] = [int]$sevCounts[$sev] + 1

        $st = [string](Get-Prop $f 'Status')
        if ([string]::IsNullOrEmpty($st)) { $st = 'Unknown' }
        if (-not $statusCounts.Contains($st)) { $statusCounts[$st] = 0 }
        $statusCounts[$st] = [int]$statusCounts[$st] + 1
    }

    $postureScore = $null
    $grade = $null
    if ($null -ne $Summary) {
        $ps = Get-Prop $Summary 'PostureScore'
        if ($null -ne $ps) { $postureScore = $ps }
        $g = Get-Prop $Summary 'Grade'
        if ($null -ne $g -and -not [string]::IsNullOrEmpty([string]$g)) { $grade = [string]$g }

        $bySev = Get-Prop $Summary 'BySeverity'
        if ($null -ne $bySev) {
            foreach ($s in $sevOrder) {
                $v = Get-Prop $bySev $s
                if ($null -ne $v) { $sevCounts[$s] = [int]$v }
            }
        }
        $byStat = Get-Prop $Summary 'ByStatus'
        if ($null -ne $byStat) {
            foreach ($p in $byStat.PSObject.Properties) {
                $statusCounts[$p.Name] = [int]$p.Value
            }
        }
    }

    $scoreText = '-'
    if ($null -ne $postureScore) { $scoreText = [string]$postureScore }
    $gradeText = '-'
    if ($null -ne $grade) { $gradeText = $grade }
    $gradeClass = Get-GradeClass $gradeText

    function Meta-Val {
        param([string] $Key)
        if ($null -eq $Meta) { return '-' }
        if ($Meta.ContainsKey($Key) -and $null -ne $Meta[$Key] -and -not [string]::IsNullOrWhiteSpace([string]$Meta[$Key])) {
            return [string]$Meta[$Key]
        }
        return '-'
    }
    $domain      = Meta-Val 'Domain'
    $forest      = Meta-Val 'Forest'
    $generatedAt = Meta-Val 'GeneratedAt'
    $mode        = Meta-Val 'Mode'

    $groups = @{}
    $groupOrder = @()
    foreach ($f in $Finding) {
        if ($null -eq $f) { continue }
        $id = [string](Get-Prop $f 'Id')
        if ([string]::IsNullOrEmpty($id)) { $id = '(no id)' }
        if (-not $groups.ContainsKey($id)) {
            $groups[$id] = New-Object System.Collections.ArrayList
            $groupOrder += $id
        }
        [void]$groups[$id].Add($f)
    }

    $sortedGroupIds = $groupOrder | Sort-Object -Property `
        @{ Expression = { $n = 9999; if ($_ -match 'ESC0*(\d+)') { $n = [int]$Matches[1] }; $n } }, `
        @{ Expression = { $_ } }

    $totalFindings = @($Finding).Count

    function Build-CaPanel {
        param($M)
        if ($null -eq $M -or -not $M.ContainsKey('CaStatus') -or $null -eq $M['CaStatus']) { return '' }
        $ca = $M['CaStatus']
        $servers = @($ca.Servers)
        $disc = @($ca.Discrepancies)

        $rows = ''
        foreach ($s in $servers) {
            if ($s.Reachable) { $rDot = '<span class="dot ok" title="Reachable"></span>'; $rTxt = (Encode ([string]$s.ReachableMethod)) }
            else { $rDot = '<span class="dot bad" title="Unreachable"></span>'; $rTxt = 'unreachable' }

            if ($null -eq $s.CertutilAlive) { $pDot = '<span class="dot warn" title="Not tested"></span>'; $pTxt = 'n/a' }
            elseif ($s.CertutilAlive) { $pDot = '<span class="dot ok" title="Alive"></span>'; $pTxt = 'alive' }
            else { $pDot = '<span class="dot bad" title="No response"></span>'; $pTxt = 'no response' }

            if ($s.InCertPublishers) { $cpDot = '<span class="dot ok" title="Present"></span>'; $cpTxt = 'member' }
            else { $cpDot = '<span class="dot bad" title="Missing"></span>'; $cpTxt = 'missing' }

            $rows += '<tr>'
            $rows += '<td class="ca-name">' + (Encode ([string]$s.CaName)) + '</td>'
            $rows += '<td class="ca-host">' + (Encode ([string]$s.DnsHostName)) + '</td>'
            $rows += '<td>' + $rDot + '<span class="ca-lbl">' + $rTxt + '</span></td>'
            $rows += '<td>' + $pDot + '<span class="ca-lbl">' + $pTxt + '</span></td>'
            $rows += '<td>' + $cpDot + '<span class="ca-lbl">' + $cpTxt + '</span></td>'
            $rows += '</tr>'
        }
        if ($rows -eq '') { $rows = '<tr><td colspan="5" class="ca-empty">No Enrollment Service (Enterprise CA) objects were found.</td></tr>' }

        if ($disc.Count -gt 0) {
            $items = ''
            foreach ($d in $disc) {
                $items += '<li><span class="disc-type">' + (Encode ([string]$d.Type)) + '</span> <b>' + (Encode ([string]$d.Host)) + '</b> &mdash; ' + (Encode ([string]$d.Detail)) + '</li>'
            }
            $discHtml = '<div class="ca-disc bad-box"><h4>Discrepancies (' + $disc.Count + ')</h4><ul>' + $items + '</ul></div>'
        }
        else {
            $discHtml = '<div class="ca-disc ok-box">No discrepancies detected: Enrollment Services, certutil ping, and Cert Publishers all agree.</div>'
        }

        $panel = '<div class="panel">'
        $panel += '<h2>Certificate Authorities</h2>'
        $panel += '<p class="ca-sub">Enterprise CA objects (Enrollment Services) cross-checked against certutil -ping and the Cert Publishers group.</p>'
        $panel += '<table class="ca-table"><thead><tr>'
        $panel += '<th>CA</th><th>Host</th><th>Reachable</th><th>certutil ping</th><th>Cert Publishers</th>'
        $panel += '</tr></thead><tbody>' + $rows + '</tbody></table>'
        $panel += $discHtml
        $panel += '</div>'
        return $panel
    }

    $caPanelHtml = Build-CaPanel -M $Meta

    function Build-ExportsPanel {
        param($M)
        if ($null -eq $M -or -not $M.ContainsKey('CaExports') -or $null -eq $M['CaExports']) { return '' }
        $runs = @($M['CaExports'])
        if ($runs.Count -eq 0) { return '' }

        $svgReg    = '<svg viewBox="0 0 24 24"><path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/><path d="M3 8v5"/><path d="M21 8v5"/></svg>'
        $svgDoc    = '<svg viewBox="0 0 24 24"><path d="M6 2h8l4 4v16H6z"/><path d="M14 2v4h4"/></svg>'
        $svgList   = '<svg viewBox="0 0 24 24"><path d="M8 6h12M8 12h12M8 18h12"/><path d="M4 6h.01M4 12h.01M4 18h.01"/></svg>'
        $svgShield = '<svg viewBox="0 0 24 24"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z"/></svg>'
        $svgFolder = '<svg viewBox="0 0 24 24"><path d="M3 7h6l2 2h10v10H3z"/></svg>'
        $svgLock   = '<svg viewBox="0 0 24 24"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>'
        $svgServer = '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.01M8 16.5h.01"/></svg>'
        $svgCrl    = '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M6 6l12 12"/></svg>'

        $rowsAll = ''
        foreach ($run in $runs) {
            if ($null -eq $run) { continue }
            $caLabel = [string]$run.CaName
            if ([string]::IsNullOrWhiteSpace($caLabel)) { $caLabel = 'Certification Authority' }
            $caHost = [string]$run.ComputerName
            $folder = [string]$run.FolderPath

            $jobRows = ''
            foreach ($j in @($run.Jobs)) {
                if ($null -eq $j) { continue }
                $jn = [string]$j.Job
                $dt = [string]$j.Detail
                if ($j.Success) { $cls = 'ok'; $pill = '<span class="exp-pill done">Done</span>' }
                elseif ($dt -match 'local-only|skipped') { $cls = 'warn'; $pill = '<span class="exp-pill skip">Skipped</span>' }
                else { $cls = 'bad'; $pill = '<span class="exp-pill fail">Failed</span>' }

                if ($jn -match 'Configuration') { $ic = $svgReg }
                elseif ($jn -match 'getreg') { $ic = $svgDoc }
                elseif ($jn -match 'Issued') { $ic = $svgList }
                elseif ($jn -match 'CRL') { $ic = $svgCrl }
                elseif ($jn -match 'Backup') { $ic = $svgShield }
                else { $ic = $svgDoc }

                $primary = $jn; $method = ''
                if ($jn -match '^(.*?)\s*\((.*)\)\s*$') { $primary = $Matches[1].Trim(); $method = $Matches[2].Trim() }
                switch -Regex ($primary) {
                    'CertSvc_Configuration' { $primary = 'Registry (CertSvc\Configuration)' }
                    'CA_Registry_getreg'    { $primary = 'Registry dump (certutil -getreg)' }
                    'Issued_Certificates'   { $primary = 'Issued certificates' }
                    'CRL_Lists'             { $primary = 'CRL lists' }
                    'CA_Backup'             { $primary = 'CA backup' }
                }

                $fileName = ''
                if ($j.Path) {
                    $leaf = Split-Path -Path ([string]$j.Path) -Leaf
                    if ($jn -match 'Backup|CRL') { $fileName = $leaf + '\  (folder)' } else { $fileName = $leaf }
                }
                $fileHtml = ''
                if ($fileName) { $fileHtml = '<div class="exp-file">' + (Encode $fileName) + '</div>' }
                $methodHtml = ''
                if ($method) { $methodHtml = '<span class="exp-via">' + (Encode $method) + '</span>' }
                $aclHtml = ''
                if (($jn -match 'Backup') -and ($j.AclHardened -eq $true)) {
                    $aclHtml = '<span class="exp-acl">' + $svgLock + 'ACL: Admins only</span>'
                }
                $detailHtml = ''
                if ($dt) { $detailHtml = '<div class="exp-detail">' + (Encode $dt) + '</div>' }

                $jobRows += '<div class="exp-job">'
                $jobRows += '<div class="exp-chip ' + $cls + '">' + $ic + '</div>'
                $jobRows += '<div class="exp-body"><div class="exp-title"><b>' + (Encode $primary) + '</b>' + $methodHtml + $aclHtml + '</div>' + $fileHtml + $detailHtml + '</div>'
                $jobRows += '<div class="exp-status">' + $pill + '</div>'
                $jobRows += '</div>'
            }
            if ($jobRows -eq '') { $jobRows = '<div class="exp-job"><div class="exp-body"><div class="exp-detail">No export jobs ran.</div></div></div>' }

            $hostHtml = ''
            if ($caHost) { $hostHtml = '<span>' + (Encode $caHost) + '</span>' }

            $rowsAll += '<div class="exp-run">'
            $rowsAll += '<div class="exp-head">'
            $rowsAll += '<div class="exp-ca"><span class="exp-ic">' + $svgServer + '</span><b>' + (Encode $caLabel) + '</b>' + $hostHtml + '</div>'
            $rowsAll += '<div class="exp-dest"><span class="exp-ic">' + $svgFolder + '</span><span class="exp-path">' + (Encode $folder) + '</span></div>'
            $rowsAll += '</div>'
            $rowsAll += '<div class="exp-jobs">' + $jobRows + '</div>'
            $rowsAll += '</div>'
        }

        $panel = '<div class="panel">'
        $panel += '<h2>Exports &amp; Backups</h2>'
        $panel += '<p class="exp-sub">Read-only artifacts collected from each CA - what was captured and where it was written.</p>'
        $panel += $rowsAll
        $panel += '</div>'
        return $panel
    }

    $exportsPanelHtml = Build-ExportsPanel -M $Meta

    function Build-TemplateUsagePanel {
        param($M)
        if ($null -eq $M -or -not $M.ContainsKey('UnusedTemplates') -or $null -eq $M['UnusedTemplates']) { return '' }
        $runs = @($M['UnusedTemplates'])
        if ($runs.Count -eq 0) { return '' }
        $rowsAll = ''
        foreach ($r in $runs) {
            if ($null -eq $r) { continue }
            $ca = Encode ([string]$r.CaName)
            $hostHtml = ''
            if ($r.DnsHostName) { $hostHtml = '<span>' + (Encode ([string]$r.DnsHostName)) + '</span>' }
            $pub = [int]$r.PublishedCount
            $act = [int]$r.ActiveTemplateCount
            $unused = @($r.Unused)
            if (($unused.Count -eq 0) -and (-not $r.Error)) {
                $body = '<div class="tpl-ok"><span class="dot"></span>All ' + $pub + ' published template(s) have at least one active certificate.</div>'
            }
            else {
                if ($unused.Count -gt 0) {
                    $chips = ''
                    foreach ($u in $unused) { $chips += '<span class="tpl-chip">' + (Encode ([string]$u)) + '</span>' }
                    $body = '<div class="tpl-chips">' + $chips + '</div>'
                }
                else {
                    $body = '<div class="tpl-note">No unused templates detected.</div>'
                }
                if ($r.Error) { $body += '<div class="tpl-note">Note: ' + (Encode ([string]$r.Error)) + '</div>' }
            }
            $rowsAll += '<div class="tpl-run">'
            $rowsAll += '<div class="tpl-head"><div class="tpl-ca"><b>' + $ca + '</b>' + $hostHtml + '</div>'
            $rowsAll += '<div class="tpl-stats"><span>Published <b>' + $pub + '</b></span><span>With active cert <b>' + $act + '</b></span><span>Unused <b>' + $unused.Count + '</b></span></div></div>'
            $rowsAll += '<div class="tpl-body">' + $body + '</div>'
            $rowsAll += '</div>'
        }
        $panel = '<div class="panel">'
        $panel += '<h2>Unused Published Templates</h2>'
        $panel += '<p class="tpl-sub">Templates published on a CA with no certificate that is still valid today - candidates to unpublish to reduce attack surface.</p>'
        $panel += $rowsAll
        $panel += '</div>'
        return $panel
    }

    $templateUsageHtml = Build-TemplateUsagePanel -M $Meta

    # CA management-role inventory: Manage CA / Issue and Manage Certificates
    # holders per CA, with assignments outside the default privileged groups
    # (Administrators / Domain Admins / Enterprise Admins) flagged (ESC7).
    function Build-CaRolesPanel {
        param($M)
        if ($null -eq $M -or -not $M.ContainsKey('CaRoleAssignments') -or $null -eq $M['CaRoleAssignments']) { return '' }
        $runs = @($M['CaRoleAssignments'])
        if ($runs.Count -eq 0) { return '' }

        $svgServer = '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.01M8 16.5h.01"/></svg>'

        $rowsAll = ''
        foreach ($r in $runs) {
            if ($null -eq $r) { continue }
            $caLabel = [string]$r.Name
            if ([string]::IsNullOrWhiteSpace($caLabel)) { $caLabel = 'Certification Authority' }
            $hostHtml = ''
            if ($r.DnsHostName) { $hostHtml = '<span>' + (Encode ([string]$r.DnsHostName)) + '</span>' }

            $roles = @($r.Roles)
            $nonDef = [int]$r.NonDefaultCount

            if (-not $r.AcesAvailable) {
                $flagHtml = ''
                $body = '<div class="rol-note">Security descriptor unavailable &mdash; CA unreachable or ACL not collected.</div>'
            }
            elseif ($roles.Count -eq 0) {
                $flagHtml = ''
                $body = '<div class="rol-note">No principal holds Manage CA or Issue and Manage Certificates.</div>'
            }
            else {
                if ($nonDef -gt 0) {
                    $flagHtml = '<span class="rol-flag warn">' + $nonDef + ' non-default</span>'
                } else {
                    $flagHtml = '<span class="rol-flag ok">All default</span>'
                }
                $list = ''
                foreach ($role in $roles) {
                    if ($null -eq $role) { continue }
                    $prin = [string]$role.Principal
                    if ([string]::IsNullOrWhiteSpace($prin)) { $prin = [string]$role.Sid }
                    if ([string]::IsNullOrWhiteSpace($prin)) { $prin = '(unresolved SID)' }

                    $tags = ''
                    if ($role.ManageCA)           { $tags += '<span class="rol-tag ca">Manage CA</span>' }
                    if ($role.ManageCertificates) { $tags += '<span class="rol-tag cert">Issue &amp; Manage Certs</span>' }

                    if ($role.IsDefault) {
                        $rowCls = ''
                        $mark = '<span class="rol-mark def">default</span>'
                    }
                    else {
                        $rowCls = ' nondef'
                        $mark = '<span class="rol-mark nondef">non-default</span>'
                        if ($role.IsLowPriv) { $mark += '<span class="rol-badge">low-priv (ESC7)</span>' }
                    }

                    $list += '<div class="rol-row' + $rowCls + '">'
                    $list += '<span class="rol-prin">' + (Encode $prin) + '</span>'
                    $list += '<span class="rol-tags">' + $tags + '</span>'
                    $list += '<span>' + $mark + '</span>'
                    $list += '</div>'
                }
                $body = '<div class="rol-list">' + $list + '</div>'
            }

            $rowsAll += '<div class="rol-run">'
            $rowsAll += '<div class="rol-head">'
            $rowsAll += '<div class="rol-ca"><span class="exp-ic">' + $svgServer + '</span><b>' + (Encode $caLabel) + '</b>' + $hostHtml + '</div>'
            $rowsAll += $flagHtml
            $rowsAll += '</div>'
            $rowsAll += $body
            $rowsAll += '</div>'
        }

        $panel = '<div class="panel">'
        $panel += '<h2>CA Management Roles</h2>'
        $panel += '<p class="rol-sub">Who can administer each CA (<b>Manage CA</b>) and approve/issue certificates (<b>Issue and Manage Certificates</b>). Assignments outside the default privileged groups &mdash; Administrators, Domain Admins, Enterprise Admins &mdash; are flagged for review (ESC7).</p>'
        $panel += $rowsAll
        $panel += '</div>'
        return $panel
    }

    $rolesPanelHtml = Build-CaRolesPanel -M $Meta

    $gradeSuffix = ($gradeClass -replace '^grade-', '')

    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $scoreNum = 0.0
    if ($null -ne $postureScore) {
        [double]::TryParse([string]$postureScore, [System.Globalization.NumberStyles]::Float, $inv, [ref]$scoreNum) | Out-Null
    }
    if ($scoreNum -lt 0) { $scoreNum = 0 }
    if ($scoreNum -gt 100) { $scoreNum = 100 }
    $ringOffset = ([math]::Round(326.73 * (1 - ($scoreNum / 100)), 2)).ToString($inv)

    $capNoteHtml = ''
    if ($null -ne $Summary -and $Summary.PSObject.Properties.Match('Capped').Count -gt 0 -and $Summary.Capped) {
        $worstSev = [string] $Summary.WorstVulnerableSeverity
        $capNoteHtml = '<p class="cap-note">Score capped at grade <b>' + (Encode $gradeText) +
            '</b> by a confirmed Vulnerable finding &mdash; a single such issue defines the security posture.</p>'
    }

    $sparkMap = @{ 'Critical' = 's-crit'; 'High' = 's-high'; 'Medium' = 's-med'; 'Low' = 's-low'; 'Info' = 's-info' }
    $sparkTotal = 0
    foreach ($s in $sevOrder) { if ($sevCounts.Contains($s)) { $sparkTotal += [int]$sevCounts[$s] } }
    $sparkHtml = ''
    if ($sparkTotal -le 0) {
        $sparkHtml = '<i class="s-none" style="flex:1"></i>'
    } else {
        foreach ($s in $sevOrder) {
            $c = 0
            if ($sevCounts.Contains($s)) { $c = [int]$sevCounts[$s] }
            if ($c -gt 0) { $sparkHtml += '<i class="' + $sparkMap[$s] + '" style="flex:' + $c + '"></i>' }
        }
    }

    $heroChips = ''

    $modeClass = 'mode-' + ("$mode".ToLower())

    $cardsHtml = ''
    foreach ($id in $sortedGroupIds) {
        $items = $groups[$id] | Sort-Object -Property @{ Expression = {
                $rs = Get-Prop $_ 'RiskScore'
                $n = 0.0
                if ($null -ne $rs) { [double]::TryParse([string]$rs, [ref]$n) | Out-Null }
                $n
            }; Descending = $true
        }

        $cardsHtml += '<section class="group"><h3 class="group-title">' + (Encode $id) +
                      ' <span class="group-count">' + (@($items).Count) + '</span></h3>'

        foreach ($f in $items) {
            $sev = [string](Get-Prop $f 'Severity')
            $status = [string](Get-Prop $f 'Status')
            $title = Show (Get-Prop $f 'Title')
            $affected = Show (Get-Prop $f 'AffectedObject')
            $risk = Get-Prop $f 'RiskScore'
            $riskText = Show $risk
            $remediation = Show (Get-Prop $f 'Remediation')
            $reference = Get-Prop $f 'Reference'
            $exploit = Show (Get-Prop $f 'Exploitability')

            $principals = Get-Prop $f 'Principals'
            $prinText = '-'
            if ($null -ne $principals) {
                $pl = @($principals) | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) }
                if (@($pl).Count -gt 0) {
                    $enc = @()
                    foreach ($p in $pl) { $enc += (Encode ([string]$p)) }
                    $prinText = $enc -join '<span class="sep">, </span>'
                }
            }

            $evidence = Get-Prop $f 'Evidence'
            $evHtml = '<span class="muted">-</span>'
            if ($null -ne $evidence) { $evHtml = Render-Evidence -Value $evidence -Depth 0 }

            $refHtml = '-'
            if ($null -ne $reference -and -not [string]::IsNullOrWhiteSpace([string]$reference)) {
                $refStr = [string]$reference
                if ($refStr -match '^(https?://|www\.)') {
                    $href = $refStr
                    if ($href -notmatch '^https?://') { $href = 'https://' + $href }
                    $refHtml = '<a href="' + (Encode $href) + '" rel="noopener noreferrer" target="_blank">' + (Encode $refStr) + '</a>'
                } else {
                    $refHtml = Encode $refStr
                }
            }

            $sevCls = Get-SevClass $sev
            $stCls = Get-StatusClass $status

            $cardsHtml += '<article class="card acc-' + $sevCls + '">'
            $cardsHtml += '<div class="card-head">'
            $cardsHtml += '<span class="badge status ' + $stCls + '">' + (Encode (Show $status)) + '</span>'
            $cardsHtml += '<span class="card-id">' + (Encode $id) + '</span>'
            $cardsHtml += '<span class="card-title">' + (Encode $title) + '</span>'
            $cardsHtml += '<span class="card-risk" title="RiskScore">' + (Encode $riskText) + '</span>'
            $cardsHtml += '</div>'

            $cardsHtml += '<div class="card-body">'
            $cardsHtml += '<div class="field"><span class="flabel">Affected Object</span><span class="fval mono">' + (Encode $affected) + '</span></div>'
            $cardsHtml += '<div class="field"><span class="flabel">Exploitability</span><span class="fval">' + (Encode $exploit) + '</span></div>'
            $cardsHtml += '<div class="field"><span class="flabel">Principals</span><span class="fval mono">' + $prinText + '</span></div>'
            $cardsHtml += '<div class="field wide"><span class="flabel">Evidence</span><div class="fval ev-wrap">' + $evHtml + '</div></div>'
            $cardsHtml += '<div class="field wide"><span class="flabel">Remediation</span><span class="fval">' + (Encode $remediation) + '</span></div>'
            $cardsHtml += '<div class="field wide"><span class="flabel">Reference</span><span class="fval">' + $refHtml + '</span></div>'
            $cardsHtml += '</div>'
            $cardsHtml += '</article>'
        }

        $cardsHtml += '</section>'
    }

    if ([string]::IsNullOrEmpty($cardsHtml)) {
        $cardsHtml = '<p class="muted center">No findings to display.</p>'
    }

    $css = @'
:root{
  --font-sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --font-mono:ui-monospace,SFMono-Regular,"SF Mono","Cascadia Code",Menlo,Consolas,monospace;
  --bg:#e8ecf3; --panel:#ffffff; --panel-2:#f4f7fb; --ink:#131a24; --muted:#5a6675;
  --line:#d9e0ea; --line-soft:#eef2f7; --accent:#0f7d8c; --accent-2:#0b5e6a; --on-accent:#ffffff;
  --crit:#c8102e; --high:#df5f0a; --med:#bd8600; --low:#3a72c9; --info:#6b7684; --ok:#2e9e5b;
  --gr-a:#2e9e5b; --gr-b:#68b23e; --gr-c:#cf9f0c; --gr-d:#df5f0a; --gr-f:#c8102e; --gr-na:#6b7684;
  --ring-track:#e4e9f0;
  --shadow:0 1px 3px rgba(18,28,45,.06),0 10px 26px -14px rgba(18,28,45,.14);
  --warn-bg:#fff7e6; --warn-line:#f0dca6; --warn-ink:#6f5100;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0e131a; --panel:#151c26; --panel-2:#1b2430; --ink:#e7ecf3; --muted:#94a2b4;
  --line:#28323f; --line-soft:#1f2833; --accent:#38bccc; --accent-2:#57ccda; --on-accent:#04212a;
  --crit:#f2555a; --high:#ff8a3d; --med:#e6b23c; --low:#5b95e6; --info:#8794a5; --ok:#3fbf74;
  --gr-a:#3fbf74; --gr-b:#7cc94f; --gr-c:#e6b23c; --gr-d:#ff8a3d; --gr-f:#f2555a; --gr-na:#8794a5;
  --ring-track:#232e3b;
  --shadow:0 1px 2px rgba(0,0,0,.45),0 12px 32px -16px rgba(0,0,0,.7);
  --warn-bg:#2a2413; --warn-line:#4d411f; --warn-ink:#e6c979;
}}
:root[data-theme="dark"]{
  --bg:#0e131a; --panel:#151c26; --panel-2:#1b2430; --ink:#e7ecf3; --muted:#94a2b4;
  --line:#28323f; --line-soft:#1f2833; --accent:#38bccc; --accent-2:#57ccda; --on-accent:#04212a;
  --crit:#f2555a; --high:#ff8a3d; --med:#e6b23c; --low:#5b95e6; --info:#8794a5; --ok:#3fbf74;
  --gr-a:#3fbf74; --gr-b:#7cc94f; --gr-c:#e6b23c; --gr-d:#ff8a3d; --gr-f:#f2555a; --gr-na:#8794a5;
  --ring-track:#232e3b;
  --shadow:0 1px 2px rgba(0,0,0,.45),0 12px 32px -16px rgba(0,0,0,.7);
  --warn-bg:#2a2413; --warn-line:#4d411f; --warn-ink:#e6c979;
}
*{box-sizing:border-box}
html{color-scheme:light dark}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font-sans);
  font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}
.wrap{max-width:1140px;margin:0 auto;padding:22px 20px 72px}
a{color:var(--accent);text-underline-offset:2px}
.mono{font-family:var(--font-mono);font-size:12.5px}
.muted{color:var(--muted)} .center{text-align:center}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
.sep{color:var(--muted)}

/* masthead + severity spark */
.masthead{display:flex;align-items:center;justify-content:space-between;gap:20px 28px;flex-wrap:wrap;
  padding:16px 22px;background:var(--panel);border:1px solid var(--line);border-bottom:none;
  border-radius:16px 16px 0 0;box-shadow:var(--shadow)}
.brand{display:flex;align-items:center;gap:14px;min-width:0}
.brand-logo{width:46px;height:46px;flex:0 0 auto;object-fit:contain;border-radius:11px;
  background:var(--panel-2);padding:5px;border:1px solid var(--line-soft)}
.brand-name{font-size:21px;font-weight:800;letter-spacing:-.01em;line-height:1}
.brand-tag{font-size:12px;color:var(--muted);letter-spacing:.02em;margin-top:3px}
.run-meta{display:flex;align-items:center;gap:22px;flex-wrap:wrap}
.run-meta>div{display:flex;flex-direction:column;gap:2px}
.run-meta span{font-size:9.5px;text-transform:uppercase;letter-spacing:.09em;color:var(--muted)}
.run-meta b{font-size:12.5px;font-weight:600;font-family:var(--font-mono)}
.mode{padding:1px 8px;border-radius:20px;border:1px solid var(--line);text-transform:capitalize}
.mode-exploit{color:var(--crit);border-color:var(--crit)}
.mode-detect{color:var(--ok);border-color:var(--ok)}
.mode-dry-run{color:var(--med);border-color:var(--med)}
.theme-toggle{width:34px;height:34px;border-radius:9px;border:1px solid var(--line);
  background:var(--panel-2);color:var(--ink);font-size:16px;cursor:pointer;line-height:1}
.theme-toggle:hover{border-color:var(--accent);color:var(--accent)}
.sev-spark{display:flex;height:5px;overflow:hidden;border:1px solid var(--line);border-top:none;
  border-radius:0 0 16px 16px;margin-bottom:22px}
.sev-spark i{display:block;height:100%}
.sev-spark .s-crit{background:var(--crit)}.sev-spark .s-high{background:var(--high)}
.sev-spark .s-med{background:var(--med)}.sev-spark .s-low{background:var(--low)}
.sev-spark .s-info{background:var(--info)}.sev-spark .s-none{background:var(--line)}

/* hero + posture ring */
.hero{display:flex;gap:26px;align-items:center;flex-wrap:wrap;background:var(--panel);
  border:1px solid var(--line);border-radius:16px;padding:22px 26px;margin-bottom:22px;box-shadow:var(--shadow)}
.ring-wrap{position:relative;flex:0 0 auto;display:flex;flex-direction:column;align-items:center;gap:8px}
.ring-prog{transition:stroke-dashoffset .9s ease}
.ring-prog.g-a{stroke:var(--gr-a)}.ring-prog.g-b{stroke:var(--gr-b)}.ring-prog.g-c{stroke:var(--gr-c)}
.ring-prog.g-d{stroke:var(--gr-d)}.ring-prog.g-f{stroke:var(--gr-f)}.ring-prog.g-na{stroke:var(--gr-na)}
.ring-num{font-family:var(--font-sans);font-size:30px;font-weight:800;fill:var(--ink)}
.ring-den{font-size:11px;fill:var(--muted);letter-spacing:.05em}
.grade-pill{font-size:13px;font-weight:800;letter-spacing:.03em;padding:2px 14px;border-radius:20px;color:var(--on-accent)}
.grade-pill.g-a{background:var(--gr-a)}.grade-pill.g-b{background:var(--gr-b)}.grade-pill.g-c{background:var(--gr-c)}
.grade-pill.g-d{background:var(--gr-d)}.grade-pill.g-f{background:var(--gr-f)}.grade-pill.g-na{background:var(--gr-na)}
.hero-body{flex:1 1 320px;min-width:260px}
.hero-body h1{margin:0 0 4px;font-size:23px;font-weight:800;letter-spacing:-.01em;text-wrap:balance}
.hero-sub{margin:0 0 12px;color:var(--muted);font-size:13px}
.cap-note{margin:0 0 14px;font-size:12px;color:var(--crit);background:rgba(200,16,46,.08);
  border:1px solid var(--crit);border-radius:8px;padding:7px 11px;display:inline-block}
.chips-strip{display:flex;gap:10px;flex-wrap:wrap}

/* severity chips (hero) */
.chip{border-radius:10px;padding:9px 14px;min-width:78px;display:flex;flex-direction:column;
  align-items:center;background:var(--panel-2);border:1px solid var(--line);border-top:3px solid var(--info)}
.chip-num{font-size:20px;font-weight:800;line-height:1;font-family:var(--font-mono);
  font-variant-numeric:tabular-nums;color:var(--ink)}
.chip-lbl{font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;margin-top:3px;color:var(--muted)}
.chip.critical{border-top-color:var(--crit)} .chip.high{border-top-color:var(--high)}
.chip.medium{border-top-color:var(--med)} .chip.low{border-top-color:var(--low)}
.chip.info{border-top-color:var(--info)}

/* panels / sections */
.panel{background:var(--panel);border:1px solid var(--line);border-radius:16px;
  padding:20px 22px;margin-bottom:22px;box-shadow:var(--shadow)}
.panel h2{margin:0 0 14px;font-size:15px;font-weight:700;border-left:3px solid var(--accent);padding-left:10px}
.cols{display:flex;flex-wrap:wrap;gap:26px}
.col{flex:1 1 320px;min-width:280px}
.col h4{margin:0 0 10px;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}

/* bars */
.bar-row{display:flex;align-items:center;gap:10px;margin:6px 0}
.bar-label{width:104px;font-size:12.5px;flex:0 0 auto}
.bar-track{flex:1 1 auto;background:var(--panel-2);border:1px solid var(--line-soft);border-radius:6px;height:16px;overflow:hidden}
.bar-fill{height:100%;border-radius:6px;min-width:2px}
.bar-count{width:34px;text-align:right;font-variant-numeric:tabular-nums;font-size:12.5px;flex:0 0 auto;font-family:var(--font-mono)}
.bar-fill.sev-critical{background:var(--crit)} .bar-fill.sev-high{background:var(--high)}
.bar-fill.sev-medium{background:var(--med)} .bar-fill.sev-low{background:var(--low)}
.bar-fill.sev-info{background:var(--info)}
.bar-fill.st-vuln{background:var(--crit)} .bar-fill.st-pot{background:var(--high)}
.bar-fill.st-manual{background:var(--low)} .bar-fill.st-ok{background:var(--ok)}
.bar-fill.st-err{background:var(--info)} .bar-fill.st-unknown{background:var(--info)}
/* CA inventory */
.ca-sub{color:var(--muted);font-size:12.5px;margin:0 0 10px 0}
.ca-table{width:100%;border-collapse:collapse;font-size:13px;margin-top:2px}
.ca-table th{text-align:left;font-weight:600;color:var(--muted);padding:6px 10px;border-bottom:1px solid var(--line)}
.ca-table td{padding:7px 10px;border-bottom:1px solid var(--line-soft);vertical-align:middle}
.ca-table .ca-name{font-weight:600}
.ca-table .ca-host{font-family:var(--font-mono);font-size:12px}
.ca-lbl{margin-left:7px;color:var(--muted);font-size:12px}
.ca-empty{color:var(--muted);text-align:center;font-style:italic}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;vertical-align:middle;box-shadow:0 0 0 2px rgba(0,0,0,.06)}
.dot.ok{background:var(--ok)} .dot.bad{background:var(--crit)} .dot.warn{background:var(--med)}
.ca-disc{margin-top:14px;padding:10px 12px;border-radius:8px;font-size:13px}
.ca-disc h4{margin:0 0 6px 0}
.ca-disc ul{margin:0;padding-left:18px}
.ca-disc li{margin:3px 0}
.disc-type{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;color:var(--crit);margin-right:4px}
.bad-box{background:rgba(200,16,46,.08);border:1px solid var(--crit)}
.ok-box{background:rgba(46,158,91,.08);border:1px solid var(--ok);color:var(--muted)}
/* Exports & Backups */
.exp-sub{color:var(--muted);font-size:12.5px;margin:0 0 14px 0}
.exp-run{border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:14px;background:var(--panel-2)}
.exp-run:last-child{margin-bottom:0}
.exp-head{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px;padding:11px 14px;background:var(--panel);border-bottom:1px solid var(--line)}
.exp-ca{display:flex;align-items:center;gap:9px;min-width:0}
.exp-ca b{font-size:14px}
.exp-ca span{color:var(--muted);font-size:12px}
.exp-ic{display:inline-flex;flex:0 0 auto}
.exp-ca .exp-ic{color:var(--accent)}
.exp-ic svg{width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.exp-dest{display:flex;align-items:center;gap:7px;min-width:0;max-width:100%}
.exp-dest .exp-ic{color:var(--muted)}
.exp-path{font-family:var(--font-mono);font-size:11.5px;color:var(--ink);background:var(--panel-2);border:1px solid var(--line-soft);border-radius:6px;padding:3px 8px;overflow-x:auto;white-space:nowrap;max-width:100%}
.exp-jobs{display:flex;flex-direction:column}
.exp-job{display:flex;align-items:flex-start;gap:11px;padding:10px 14px;border-top:1px solid var(--line-soft)}
.exp-job:first-child{border-top:none}
.exp-chip{flex:0 0 auto;width:26px;height:26px;border-radius:7px;display:flex;align-items:center;justify-content:center;background:var(--panel);border:1px solid var(--line)}
.exp-chip svg{width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}
.exp-chip.ok{color:var(--ok)} .exp-chip.bad{color:var(--crit)} .exp-chip.warn{color:var(--med)}
.exp-body{flex:1 1 auto;min-width:0}
.exp-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.exp-title b{font-size:13px}
.exp-via{color:var(--muted);font-size:11px;font-family:var(--font-mono)}
.exp-file{color:var(--muted);font-size:11.5px;font-family:var(--font-mono);margin-top:2px;word-break:break-all}
.exp-detail{color:var(--muted);font-size:11.5px;margin-top:3px}
.exp-status{flex:0 0 auto;align-self:center}
.exp-pill{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:3px 9px;border-radius:999px;border:1px solid transparent;white-space:nowrap}
.exp-pill.done{color:var(--ok);background:rgba(46,158,91,.10);border-color:rgba(46,158,91,.35)}
.exp-pill.fail{color:var(--crit);background:rgba(200,16,46,.10);border-color:rgba(200,16,46,.35)}
.exp-pill.skip{color:var(--med);background:rgba(189,134,0,.12);border-color:rgba(189,134,0,.35)}
.exp-acl{display:inline-flex;align-items:center;gap:5px;font-size:10.5px;font-weight:600;color:var(--ok);background:rgba(46,158,91,.10);border:1px solid rgba(46,158,91,.30);border-radius:999px;padding:2px 8px}
.exp-acl svg{width:12px;height:12px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
/* Template usage */
.tpl-sub{color:var(--muted);font-size:12.5px;margin:0 0 14px 0}
.tpl-run{border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:12px;background:var(--panel-2)}
.tpl-run:last-child{margin-bottom:0}
.tpl-head{display:flex;flex-wrap:wrap;align-items:center;gap:10px;justify-content:space-between;padding:10px 14px;background:var(--panel);border-bottom:1px solid var(--line)}
.tpl-ca{display:flex;align-items:center;gap:9px;min-width:0}
.tpl-ca b{font-size:14px}
.tpl-ca span{color:var(--muted);font-size:12px}
.tpl-stats{display:flex;gap:14px;font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.tpl-stats b{color:var(--ink);font-weight:600}
.tpl-body{padding:12px 14px}
.tpl-chips{display:flex;flex-wrap:wrap;gap:7px}
.tpl-chip{display:inline-block;font-size:12px;font-family:var(--font-mono);padding:4px 10px;border-radius:6px;color:var(--med);background:rgba(189,134,0,.10);border:1px solid rgba(189,134,0,.35)}
.tpl-ok{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12.5px}
.tpl-note{color:var(--muted);font-size:12px;margin-top:6px}
/* CA management roles */
.rol-sub{color:var(--muted);font-size:12.5px;margin:0 0 14px 0}
.rol-run{border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:12px;background:var(--panel-2)}
.rol-run:last-child{margin-bottom:0}
.rol-head{display:flex;flex-wrap:wrap;align-items:center;gap:10px;justify-content:space-between;padding:10px 14px;background:var(--panel);border-bottom:1px solid var(--line)}
.rol-ca{display:flex;align-items:center;gap:9px;min-width:0}
.rol-ca b{font-size:14px}
.rol-ca span{color:var(--muted);font-size:12px}
.rol-ca .exp-ic{color:var(--accent)}
.rol-flag{font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:3px 10px;border-radius:999px;white-space:nowrap;border:1px solid transparent}
.rol-flag.warn{color:var(--crit);background:rgba(200,16,46,.10);border-color:rgba(200,16,46,.35)}
.rol-flag.ok{color:var(--ok);background:rgba(46,158,91,.10);border-color:rgba(46,158,91,.35)}
.rol-list{display:flex;flex-direction:column}
.rol-row{display:flex;align-items:center;gap:11px;flex-wrap:wrap;padding:9px 14px;border-top:1px solid var(--line-soft)}
.rol-row:first-child{border-top:none}
.rol-row.nondef{background:rgba(200,16,46,.05)}
.rol-prin{flex:1 1 240px;min-width:0;font-family:var(--font-mono);font-size:12.5px;color:var(--ink);word-break:break-all}
.rol-tags{display:flex;gap:6px;flex-wrap:wrap}
.rol-tag{font-size:10.5px;font-weight:600;padding:2px 8px;border-radius:6px;white-space:nowrap;border:1px solid var(--line)}
.rol-tag.ca{color:var(--accent)}
.rol-tag.cert{color:var(--muted)}
.rol-mark{flex:0 0 auto;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.rol-mark.def{color:var(--muted);font-weight:600;text-transform:none;font-size:11px}
.rol-mark.nondef{color:var(--crit)}
.rol-badge{display:inline-block;font-size:10px;font-weight:700;padding:1px 7px;border-radius:999px;margin-left:6px;color:var(--med);background:rgba(189,134,0,.12);border:1px solid rgba(189,134,0,.35);text-transform:uppercase;letter-spacing:.03em}
.rol-note{color:var(--muted);font-size:12px;padding:11px 14px}

/* groups + cards */
.group{margin-bottom:22px}
.group-title{font-size:15px;font-weight:700;margin:0 0 10px;display:flex;align-items:center;gap:9px;
  padding-bottom:6px;border-bottom:2px solid var(--line)}
.group-count{background:var(--panel-2);border:1px solid var(--line);color:var(--muted);border-radius:20px;
  padding:1px 10px;font-size:12px;font-weight:600;font-variant-numeric:tabular-nums}
.card{background:var(--panel);border:1px solid var(--line);border-left-width:5px;border-radius:12px;
  padding:0;margin-bottom:12px;overflow:hidden;box-shadow:var(--shadow)}
.card-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:12px 16px;background:var(--panel-2);
  border-bottom:1px solid var(--line)}
.card-id{font-weight:700;font-size:13.5px;font-family:var(--font-mono)}
.card-title{font-size:13.5px;flex:1 1 240px}
.card-risk{margin-left:auto;font-weight:700;font-size:15px;background:var(--panel);border:1px solid var(--line);
  border-radius:8px;padding:3px 10px;font-variant-numeric:tabular-nums;font-family:var(--font-mono)}
.badge{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;
  padding:3px 9px;border-radius:20px;color:var(--on-accent)}
.badge.sev.critical{background:var(--crit)} .badge.sev.high{background:var(--high)}
.badge.sev.medium{background:var(--med)} .badge.sev.low{background:var(--low)} .badge.sev.info{background:var(--info)}
.badge.status{color:var(--on-accent)}
.st-vuln{background:var(--crit)} .st-pot{background:var(--high)} .st-manual{background:var(--low)}
.st-ok{background:var(--ok)} .st-err{background:var(--info)} .st-unknown{background:var(--info)}
.card-body{padding:12px 16px;display:flex;flex-wrap:wrap;gap:10px 24px}
.field{flex:1 1 240px;min-width:220px;display:flex;flex-direction:column;gap:3px}
.field.wide{flex:1 1 100%}
.flabel{font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
.fval{font-size:13px;word-break:break-word}
.ev-wrap{overflow-x:auto;max-width:100%}

/* evidence tables */
table.kv{border-collapse:collapse;width:100%;font-size:12.5px;margin:2px 0}
table.kv th{text-align:left;vertical-align:top;color:var(--muted);font-weight:600;
  padding:3px 10px 3px 0;white-space:nowrap;width:1%}
table.kv td{vertical-align:top;padding:3px 0;border-bottom:1px solid var(--line-soft);font-family:var(--font-mono)}
table.kv table.kv td{font-family:var(--font-sans)}
table.kv table.kv{margin:0}
ul.ev-list{margin:2px 0;padding-left:18px}

/* severity accents on card left border by first badge */
.card.acc-critical{border-left-color:var(--crit)} .card.acc-high{border-left-color:var(--high)}
.card.acc-medium{border-left-color:var(--med)} .card.acc-low{border-left-color:var(--low)}
.card.acc-info{border-left-color:var(--info)}

/* footer */
.footer{margin-top:28px;border-top:1px solid var(--line);padding-top:16px;color:var(--muted);font-size:12px}
.footer .disc{background:var(--warn-bg);border:1px solid var(--warn-line);color:var(--warn-ink);border-radius:10px;
  padding:12px 14px;margin-bottom:12px}
.footer .disc strong{color:var(--warn-ink)}

@media (max-width:640px){
  .masthead{padding:14px 16px}
  .card-body{gap:10px}
  .field{flex:1 1 100%}
}
'@

    $title = 'AD CS Security Assessment Report'

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>$(Encode $title)</title>
<style>
$css
</style>
</head>
<body>
<div class="wrap">

  <header class="masthead">
    <div class="brand">
      $(if ($logoDataUri) { '<img class="brand-logo" src="' + $logoDataUri + '" alt="Company logo" />' })
      <div class="brand-txt">
        <div class="brand-name">ESCX</div>
        <div class="brand-tag">AD CS ESC Security Assessment</div>
      </div>
    </div>
    <div class="run-meta">
      <div><span>Domain</span><b>$(Encode $domain)</b></div>
      <div><span>Mode</span><b class="mode $modeClass">$(Encode $mode)</b></div>
      <div><span>Generated</span><b>$(Encode $generatedAt)</b></div>
      <button class="theme-toggle" type="button" title="Toggle light / dark" aria-label="Toggle light or dark theme" onclick="__esctheme()">&#9680;</button>
    </div>
  </header>
  <div class="sev-spark" role="img" aria-label="Severity mix">$sparkHtml</div>

  <section class="hero">
    <div class="ring-wrap">
      <svg class="ring" viewBox="0 0 120 120" width="132" height="132" role="img" aria-label="Posture score $(Encode $scoreText) of 100">
        <circle class="ring-bg" cx="60" cy="60" r="52" fill="none" stroke="var(--ring-track)" stroke-width="12"/>
        <circle class="ring-prog g-$gradeSuffix" cx="60" cy="60" r="52" fill="none" stroke-width="12" stroke-linecap="round"
                stroke-dasharray="326.73" stroke-dashoffset="$ringOffset" transform="rotate(-90 60 60)"/>
        <text class="ring-num" x="60" y="58" text-anchor="middle">$(Encode $scoreText)</text>
        <text class="ring-den" x="60" y="72" text-anchor="middle">/ 100</text>
      </svg>
      <div class="grade-pill g-$gradeSuffix">$(Encode $gradeText)</div>
    </div>
    <div class="hero-body">
      <h1>AD CS Security Posture</h1>
      <p class="hero-sub">Read-only, non-destructive ESC1&ndash;ESC16 assessment &middot; $totalFindings findings</p>
      $capNoteHtml
    </div>
  </section>

  $caPanelHtml

  $rolesPanelHtml

  $templateUsageHtml

  <div class="panel">
    <h2>Findings</h2>
    $cardsHtml
  </div>

  $exportsPanelHtml

  <div class="footer">
    <div class="disc">
      <strong>Read-only / non-destructive assessment.</strong>
      This report was produced by a passive Active Directory Certificate Services (AD CS)
      posture assessment. The tooling only <em>reads</em> configuration, templates, CA
      settings and ACLs &mdash; it never requests, issues, submits, modifies, or deletes
      certificates or any directory object. No exploitation was performed; findings describe
      <em>potential</em> misconfigurations that warrant review.
    </div>
    <div>
      <strong>Ethical-use note.</strong> Use these results solely to defend and remediate
      systems you are authorized to assess. Do not use this information to gain unauthorized
      access. Validate each finding in context before acting, and follow your organization's
      change-management process for remediation.
    </div>
    <div style="margin-top:10px">Generated $(Encode $generatedAt) &middot; schemaVersion 1.0</div>
  </div>

</div>
<script>
(function(){var K="escx-theme";try{var s=localStorage.getItem(K);if(s)document.documentElement.setAttribute("data-theme",s);}catch(e){}
window.__esctheme=function(){var r=document.documentElement,c=r.getAttribute("data-theme");
if(!c)c=(window.matchMedia&&window.matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light";
var n=c==="dark"?"light":"dark";r.setAttribute("data-theme",n);try{localStorage.setItem(K,n);}catch(e){}};})();
</script>
</body>
</html>
"@

    $dir = Split-Path -Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $html, $utf8NoBom)

    return $Path
}
