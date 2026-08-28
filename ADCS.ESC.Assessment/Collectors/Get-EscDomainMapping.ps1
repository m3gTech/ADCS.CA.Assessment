function Get-EscDomainMapping {
    <#
    .SYNOPSIS
        Reads certificate-mapping registry settings from domain controllers.
    .DESCRIPTION
        For each domain controller, remotely reads (read-only) two REG_DWORD
        values that govern certificate-to-account mapping strength:
          - HKLM\SYSTEM\CurrentControlSet\Services\Kdc\
              StrongCertificateBindingEnforcement
          - HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\
              CertificateMappingMethods
        and maps them to DcMapping:
          DomainController, StrongCertificateBindingEnforcement(int),
          CertificateMappingMethods(int), WeakSchannelMapping(bool), Reachable(bool)

        WeakSchannelMapping = (CertificateMappingMethods -band 0x4) -ne 0
        (0x4 = UPN mapping, considered weak for ESC10).

        If remote registry is unreachable, Reachable=$false and the int values
        are left null. Offline mode: pass -InputObject with the field values.
    .PARAMETER DomainController
        Optional list of DC host names. Auto-discovered from the current domain
        when omitted.
    .PARAMETER InputObject
        Optional array of offline records.
    .OUTPUTS
        [pscustomobject] DcMapping[].
    .EXAMPLE
        Get-EscDomainMapping -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]] $DomainController,

        [Parameter(Mandatory = $false)]
        [object[]] $InputObject
    )

    $build = {
        param($dc, $strong, $methods, $reachable)
        $weak = $null
        if ($null -ne $methods) {
            $weak = ((([int]$methods) -band 0x4) -ne 0)
        }
        $strongOut = $null
        if ($null -ne $strong) { $strongOut = [int] $strong }
        $methodsOut = $null
        if ($null -ne $methods) { $methodsOut = [int] $methods }

        return [pscustomobject]@{
            DomainController                    = $dc
            StrongCertificateBindingEnforcement = $strongOut
            CertificateMappingMethods           = $methodsOut
            WeakSchannelMapping                 = $weak
            Reachable                           = $reachable
        }
    }

    if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
        Write-EscLog -Component 'DomainMapping' -Message ("Offline mode: transforming {0} fixture record(s)." -f @($InputObject).Count)
        $out = @()
        foreach ($rec in $InputObject) {
            $reachable = $true
            if ($null -ne $rec.Reachable) { $reachable = [bool] $rec.Reachable }
            $out += (& $build ([string]$rec.DomainController) $rec.StrongCertificateBindingEnforcement $rec.CertificateMappingMethods $reachable)
        }
        return @($out)
    }

    $dcs = @($DomainController)
    if (@($dcs).Count -eq 0) {
        try {
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            foreach ($dc in $domain.DomainControllers) { $dcs += $dc.Name }
        }
        catch {
            Write-EscLog -Component 'DomainMapping' -Level Warning -Message ("Could not enumerate domain controllers: {0}" -f $_.Exception.Message)
        }
    }
    $dcs = @($dcs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

    $localShort = [string] $env:COMPUTERNAME
    $localFqdn  = $localShort
    try { $localFqdn = [System.Net.Dns]::GetHostEntry($localShort).HostName } catch { }

    $out = @()
    foreach ($dc in $dcs) {
        $strong = $null
        $methods = $null
        $reachable = $false
        $base = $null
        try {
            $dcShort = ($dc -split '\.')[0]
            $isLocal = ($dc -ieq 'localhost' -or $dc -ieq '.' -or $dc -ieq $localShort -or
                        $dc -ieq $localFqdn -or $dcShort -ieq $localShort)
            if ($isLocal) {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Default)
            }
            else {
                $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $dc)
            }
            $reachable = $true

            $kdc = $base.OpenSubKey('SYSTEM\CurrentControlSet\Services\Kdc')
            if ($null -ne $kdc) {
                $v = $kdc.GetValue('StrongCertificateBindingEnforcement')
                if ($null -ne $v) { $strong = [int] $v }
                $kdc.Close()
            }

            $schannel = $base.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL')
            if ($null -ne $schannel) {
                $v = $schannel.GetValue('CertificateMappingMethods')
                if ($null -ne $v) { $methods = [int] $v }
                $schannel.Close()
            }
        }
        catch {
            $reachable = $false
            Write-EscLog -Component 'DomainMapping' -Level Warning -Message ("Remote registry read failed for '{0}': {1}" -f $dc, $_.Exception.Message)
        }
        finally {
            if ($null -ne $base) { try { $base.Close() } catch { } }
        }

        $out += (& $build $dc $strong $methods $reachable)
    }

    Write-EscLog -Component 'DomainMapping' -Message ("Collected mapping settings for {0} DC(s)." -f @($out).Count)
    return @($out)
}
