function Get-EscEnrollmentService {
    <#
    .SYNOPSIS
        Enumerates pKIEnrollmentService (Enterprise CA) objects (read-only).
    .DESCRIPTION
        Reads objects under
        CN=Enrollment Services,CN=Public Key Services,CN=Services,
        CN=Configuration,<configNC> via LDAP (search only) and maps each to the
        CA schema:
            Name, DnsHostName, DN, PublishedTemplates(string[]), CaCertificateThumbprint

        CaCertificateThumbprint is computed (SHA1) from the cACertificate blob
        when present. Offline mode: pass -InputObject with property bags.
    .PARAMETER Server
        Optional DC/server to bind to.
    .PARAMETER ConfigurationNamingContext
        Optional config NC DN (auto-detected from RootDSE when omitted).
    .PARAMETER InputObject
        Optional array of raw property bags (offline mode).
    .OUTPUTS
        [pscustomobject] CA[].
    .EXAMPLE
        Get-EscEnrollmentService -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $ConfigurationNamingContext,

        [Parameter(Mandatory = $false)]
        [object[]] $InputObject
    )

    $map = {
        param($bag)

        $getFirst = {
            param($n)
            $k = $n.ToLowerInvariant()
            if ($bag.ContainsKey($k)) {
                $v = $bag[$k]
                if ($v -is [System.Array]) { if ($v.Length -gt 0) { return $v[0] } else { return $null } }
                return $v
            }
            return $null
        }
        $getAll = {
            param($n)
            $k = $n.ToLowerInvariant()
            if ($bag.ContainsKey($k)) {
                $v = $bag[$k]
                if ($null -eq $v) { return @() }
                if ($v -is [System.Array]) { return @($v) }
                return @($v)
            }
            return @()
        }

        $name = [string] (& $getFirst 'cn')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = [string] (& $getFirst 'name') }

        $thumb = $null
        try {
            $caCert = & $getFirst 'cACertificate'
            if ($null -ne $caCert -and $caCert -is [byte[]] -and $caCert.Length -gt 0) {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]]$caCert)
                $thumb = $cert.Thumbprint
            }
        }
        catch {
            $thumb = $null
        }

        return [pscustomobject]@{
            Name                    = $name
            DnsHostName             = [string] (& $getFirst 'dNSHostName')
            DN                      = [string] (& $getFirst 'distinguishedName')
            PublishedTemplates      = @(& $getAll 'certificateTemplates')
            CaCertificateThumbprint = $thumb
        }
    }

    if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
        Write-EscLog -Component 'EnrollmentSvc' -Message ("Offline mode: transforming {0} fixture record(s)." -f @($InputObject).Count)
        $out = @()
        foreach ($rec in $InputObject) {
            $bag = $rec
            if ($rec -isnot [hashtable]) {
                if ($rec -is [System.DirectoryServices.SearchResult]) { $bag = ConvertTo-EscPropertyBag -SearchResult $rec }
                else {
                    $bag = @{}
                    foreach ($p in $rec.PSObject.Properties) { $bag[$p.Name.ToLowerInvariant()] = @($p.Value) }
                }
            }
            $out += (& $map $bag)
        }
        return @($out)
    }

    $configNc = $ConfigurationNamingContext
    if ([string]::IsNullOrWhiteSpace($configNc)) {
        $configNc = Get-EscConfigNamingContext -Server $Server
    }
    if ([string]::IsNullOrWhiteSpace($configNc)) {
        Write-EscLog -Component 'EnrollmentSvc' -Level Warning -Message 'Could not resolve configuration naming context; returning empty set.'
        return @()
    }

    $searchRoot = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $configNc
    $props = @('cn', 'name', 'dNSHostName', 'distinguishedName', 'certificateTemplates', 'cACertificate')

    $results = Invoke-EscLdapSearch -SearchRoot $searchRoot -Filter '(objectClass=pKIEnrollmentService)' `
        -Server $Server -PropertiesToLoad $props -SearchScope 'OneLevel'

    Write-EscLog -Component 'EnrollmentSvc' -Message ("Retrieved {0} enrollment service object(s)." -f @($results).Count)

    $out = @()
    foreach ($r in $results) {
        try {
            $bag = ConvertTo-EscPropertyBag -SearchResult $r
            $out += (& $map $bag)
        }
        catch {
            Write-EscLog -Component 'EnrollmentSvc' -Level Warning -Message ("Failed to map an enrollment service: {0}" -f $_.Exception.Message)
        }
    }
    return @($out)
}
