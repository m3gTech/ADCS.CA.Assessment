function Get-EscCaConfiguration {
    <#
    .SYNOPSIS
        Reads per-CA registry configuration via certutil -getreg (read-only).
    .DESCRIPTION
        For each supplied CA (Name + DnsHostName) runs `certutil -config
        "<host>\<CAName>" -getreg <value>` for the security-relevant values and
        maps the parsed output to the CaConfig schema:
            Name, DnsHostName, EditFlags, EditFlagsAttributeSanSet,
            InterfaceFlags, EnforceEncryptRequest, DisableExtensionList,
            SecurityAces(Ace[]), PolicyModule, Reachable

        certutil -getreg is a pure read. If certutil is unavailable or the host is
        unreachable, Reachable=$false and numeric/ACL fields are left null so the
        analyzers can mark ManualReview.

        Offline mode: pass -InputObject with records of the shape
            @{ Name=..; DnsHostName=..; Reachable=$true;
               RegText = @{ 'policy\EditFlags'='<text>'; 'CA\InterfaceFlags'='..';
                            'policy\DisableExtensionList'='..'; 'CA\Security'='..' } }
    .PARAMETER CA
        Array of CA descriptor objects (each with .Name and .DnsHostName), e.g.
        the output of Get-EscEnrollmentService.
    .PARAMETER InputObject
        Optional array of offline records (see description).
    .PARAMETER ExtraLowPrivSid
        Optional extra low-priv SIDs forwarded to the ACL parser.
    .OUTPUTS
        [pscustomobject] CaConfig[].
    .EXAMPLE
        Get-EscEnrollmentService | Get-EscCaConfiguration
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [object[]] $CA,

        [Parameter(Mandatory = $false)]
        [object[]] $InputObject,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @()
    )

    begin {
        $collected = New-Object System.Collections.ArrayList

        $valuePaths = @(
            'policy\EditFlags',
            'CA\InterfaceFlags',
            'policy\DisableExtensionList',
            'CA\Security',
            'CA\PolicyModules\Active'
        )

        if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
            Write-EscLog -Component 'CAConfig' -Message ("Offline mode: transforming {0} fixture record(s)." -f @($InputObject).Count)
            foreach ($rec in $InputObject) {
                $name = [string] $rec.Name
                $dns  = [string] $rec.DnsHostName
                $reachable = $true
                if ($null -ne $rec.Reachable) { $reachable = [bool] $rec.Reachable }
                $regText = @{}
                if ($null -ne $rec.RegText) {
                    if ($rec.RegText -is [hashtable]) { $regText = $rec.RegText }
                    else { foreach ($p in $rec.RegText.PSObject.Properties) { $regText[$p.Name] = $p.Value } }
                }
                [void]$collected.Add((ConvertTo-EscCaConfigObject -Name $name -DnsHostName $dns -RegText $regText -Reachable $reachable -ExtraLowPrivSid $ExtraLowPrivSid))
            }
        }
    }

    process {
        if ($PSBoundParameters.ContainsKey('InputObject')) { return }
        if ($null -eq $CA) { return }

        foreach ($caObj in $CA) {
            $name = [string] $caObj.Name
            $dns  = [string] $caObj.DnsHostName
            if ([string]::IsNullOrWhiteSpace($dns)) { $dns = $name }
            $config = '{0}\{1}' -f $dns, $name

            $secBytes = $null
            try {
                $localShort = [string] $env:COMPUTERNAME
                $localFqdn  = $localShort
                try { $localFqdn = [System.Net.Dns]::GetHostEntry($localShort).HostName } catch { }
                $dnsShort = ($dns -split '\.')[0]
                $isLocal = ($dns -ieq 'localhost' -or $dns -ieq $localShort -or $dns -ieq $localFqdn -or $dnsShort -ieq $localShort)
                if ($isLocal) {
                    $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
                    try {
                        $cfg = $baseKey.OpenSubKey('SYSTEM\CurrentControlSet\Services\CertSvc\Configuration')
                        if ($null -ne $cfg) {
                            $subs   = @($cfg.GetSubKeyNames())
                            $target = @($subs | Where-Object { $_ -ieq $name }) | Select-Object -First 1
                            if ([string]::IsNullOrWhiteSpace($target) -and $subs.Count -eq 1) { $target = $subs[0] }
                            if (-not [string]::IsNullOrWhiteSpace($target)) {
                                $caKey = $cfg.OpenSubKey($target)
                                if ($null -ne $caKey) {
                                    $sdVal = $caKey.GetValue('Security')
                                    if ($sdVal -is [byte[]] -and $sdVal.Length -gt 0) { $secBytes = $sdVal }
                                    $caKey.Close()
                                }
                            }
                            $cfg.Close()
                        }
                    }
                    finally { try { $baseKey.Close() } catch { } }
                }
            }
            catch {
                Write-EscLog -Component 'CAConfig' -Level Warning -Message ("Local registry read of CA security failed for '{0}': {1}" -f $name, $_.Exception.Message)
            }

            $regText = @{}
            $reachable = $true
            $anySuccess = $false

            foreach ($vp in $valuePaths) {
                $text = $null
                try {
                    $text = & certutil.exe -config $config -getreg $vp 2>&1 | Out-String
                    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($text)) {
                        $regText[$vp] = $text
                        $anySuccess = $true
                    }
                }
                catch {
                    Write-EscLog -Component 'CAConfig' -Level Warning -Message ("certutil failed for {0} [{1}]: {2}" -f $config, $vp, $_.Exception.Message)
                }
            }

            if (-not $anySuccess) {
                $reachable = $false
                Write-EscLog -Component 'CAConfig' -Level Warning -Message ("CA '{0}' unreachable or certutil unavailable; marking Reachable=false." -f $config)
            }

            if ($null -ne $secBytes) { $reachable = $true }

            [void]$collected.Add((ConvertTo-EscCaConfigObject -Name $name -DnsHostName $dns -RegText $regText -Reachable $reachable -ExtraLowPrivSid $ExtraLowPrivSid -SecurityDescriptorBytes $secBytes))
        }
    }

    end {
        return @($collected.ToArray())
    }
}
