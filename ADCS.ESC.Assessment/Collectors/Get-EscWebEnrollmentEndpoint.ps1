function Get-EscWebEnrollmentEndpoint {
    <#
    .SYNOPSIS
        Probes AD CS HTTP(S) enrollment endpoints (read-only GET/HEAD).
    .DESCRIPTION
        For each CA host, sends unauthenticated HTTP HEAD/GET requests (no body,
        no credentials, never a certificate request) to the classic Web Enrollment
        and CES/CEP paths to detect their presence and NTLM acceptance:
          - http(s)://<host>/certsrv/
          - http(s)://<host>/<CAName>_CES_Kerberos/service.svc
          - http(s)://<host>/ADPolicyProvider_CEP_Kerberos/service.svc
        and maps results to WebEndpoint:
          CaName, Url, Scheme, Reachable, NtlmSupported, EpaEnabled(bool|null),
          CesCepPresent

        NtlmSupported is inferred from a 401 WWW-Authenticate header containing
        NTLM or Negotiate. EpaEnabled cannot be reliably determined over
        unauthenticated HTTP, so it is set to $null (analyzers => ManualReview).
        CesCepPresent is set true on every record of a host when any CES/CEP path
        for that host responded.

        Offline mode: pass -InputObject with pre-populated WebEndpoint-shaped
        records to bypass live probing.
    .PARAMETER CA
        Array of CA descriptor objects (each with .Name and .DnsHostName), e.g.
        Get-EscEnrollmentService output.
    .PARAMETER Scheme
        Which schemes to probe: 'https', 'http', or 'both' (default 'both').
    .PARAMETER TimeoutSeconds
        Per-request timeout (default 8).
    .PARAMETER InputObject
        Optional array of offline records.
    .OUTPUTS
        [pscustomobject] WebEndpoint[].
    .EXAMPLE
        Get-EscEnrollmentService | Get-EscWebEnrollmentEndpoint
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [object[]] $CA,

        [Parameter(Mandatory = $false)]
        [ValidateSet('https', 'http', 'both')]
        [string] $Scheme = 'both',

        [Parameter(Mandatory = $false)]
        [int] $TimeoutSeconds = 8,

        [Parameter(Mandatory = $false)]
        [object[]] $InputObject
    )

    begin {
        $collected = New-Object System.Collections.ArrayList

        if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
            Write-EscLog -Component 'WebEnroll' -Message ("Offline mode: passing through {0} fixture record(s)." -f @($InputObject).Count)
            foreach ($rec in $InputObject) {
                $epa = $null
                if ($rec.PSObject.Properties.Name -contains 'EpaEnabled') { $epa = $rec.EpaEnabled }
                [void]$collected.Add([pscustomobject]@{
                    CaName        = [string] $rec.CaName
                    Url           = [string] $rec.Url
                    Scheme        = [string] $rec.Scheme
                    Reachable     = [bool] $rec.Reachable
                    NtlmSupported = [bool] $rec.NtlmSupported
                    EpaEnabled    = $epa
                    CesCepPresent = [bool] $rec.CesCepPresent
                })
            }
        }

        $schemes = @()
        if ($Scheme -eq 'both') { $schemes = @('https', 'http') } else { $schemes = @($Scheme) }

        $probe = {
            param($url, $timeoutSec)

            $result = @{ Reachable = $false; NtlmSupported = $false; StatusCode = $null }

            foreach ($method in @('HEAD', 'GET')) {
                try {
                    $req = [System.Net.HttpWebRequest]::Create($url)
                    $req.Method = $method
                    $req.Timeout = $timeoutSec * 1000
                    $req.AllowAutoRedirect = $false
                    $req.UserAgent = 'ADCS.ESC.Assessment (read-only probe)'
                    $resp = $req.GetResponse()
                    try {
                        $result.Reachable = $true
                        $result.StatusCode = [int] $resp.StatusCode
                        $auth = $resp.Headers['WWW-Authenticate']
                        if ($auth -match 'NTLM' -or $auth -match 'Negotiate') { $result.NtlmSupported = $true }
                    }
                    finally {
                        $resp.Close()
                    }
                    return $result
                }
                catch [System.Net.WebException] {
                    $we = $_.Exception
                    if ($null -ne $we.Response) {
                        $result.Reachable = $true
                        try {
                            $result.StatusCode = [int] $we.Response.StatusCode
                            $auth = $we.Response.Headers['WWW-Authenticate']
                            if ($auth -match 'NTLM' -or $auth -match 'Negotiate') { $result.NtlmSupported = $true }
                        }
                        catch { }
                        try { $we.Response.Close() } catch { }
                        return $result
                    }
                }
                catch {
                }
            }
            return $result
        }
    }

    process {
        if ($PSBoundParameters.ContainsKey('InputObject')) { return }
        if ($null -eq $CA) { return }

        $origCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s, $c, $ch, $e) $true }
            try { [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12 } catch { }

            foreach ($caObj in $CA) {
                $caName = [string] $caObj.Name
                $host2  = [string] $caObj.DnsHostName
                if ([string]::IsNullOrWhiteSpace($host2)) { $host2 = $caName }
                if ([string]::IsNullOrWhiteSpace($host2)) { continue }

                $encodedCa = [System.Uri]::EscapeDataString($caName)
                $paths = @(
                    @{ Path = '/certsrv/'; CesCep = $false },
                    @{ Path = ('/{0}_CES_Kerberos/service.svc' -f $encodedCa); CesCep = $true },
                    @{ Path = '/ADPolicyProvider_CEP_Kerberos/service.svc'; CesCep = $true }
                )

                $records = New-Object System.Collections.ArrayList
                $hostCesCep = $false

                foreach ($sch in $schemes) {
                    foreach ($p in $paths) {
                        $url = '{0}://{1}{2}' -f $sch, $host2, $p.Path
                        $r = & $probe $url $TimeoutSeconds
                        if ($r.Reachable) {
                            if ($p.CesCep) { $hostCesCep = $true }
                            [void]$records.Add([pscustomobject]@{
                                CaName        = $caName
                                Url           = $url
                                Scheme        = $sch
                                Reachable     = $true
                                NtlmSupported = [bool] $r.NtlmSupported
                                EpaEnabled    = $null
                                CesCepPresent = $false
                                _IsCesCep     = $p.CesCep
                            })
                        }
                    }
                }

                if ($records.Count -eq 0) {
                    $primaryScheme = $schemes[0]
                    [void]$collected.Add([pscustomobject]@{
                        CaName        = $caName
                        Url           = ('{0}://{1}/certsrv/' -f $primaryScheme, $host2)
                        Scheme        = $primaryScheme
                        Reachable     = $false
                        NtlmSupported = $false
                        EpaEnabled    = $null
                        CesCepPresent = $false
                    })
                }
                else {
                    foreach ($rec in $records) {
                        [void]$collected.Add([pscustomobject]@{
                            CaName        = $rec.CaName
                            Url           = $rec.Url
                            Scheme        = $rec.Scheme
                            Reachable     = $rec.Reachable
                            NtlmSupported = $rec.NtlmSupported
                            EpaEnabled    = $rec.EpaEnabled
                            CesCepPresent = $hostCesCep
                        })
                    }
                }
            }
        }
        finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $origCallback
        }
    }

    end {
        Write-EscLog -Component 'WebEnroll' -Message ("Collected {0} web endpoint record(s)." -f $collected.Count)
        return @($collected.ToArray())
    }
}
