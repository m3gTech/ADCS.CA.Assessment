function Get-EscCertificateTemplate {
    <#
    .SYNOPSIS
        Enumerates AD certificate templates (read-only) as Template[] objects.
    .DESCRIPTION
        Reads objects under
        CN=Certificate Templates,CN=Public Key Services,CN=Services,
        CN=Configuration,<configNC> via LDAP (search only) and maps each to the
        Template schema. Enrollment / write principals are derived
        from nTSecurityDescriptor using ConvertFrom-SecurityDescriptor.

        PublishedOnCAs is left empty here; the orchestrator (or a cross-reference
        with Get-EscEnrollmentService) fills it.

        Offline / test mode: pass -InputObject with an array of property bags
        (hashtables keyed by lowercase attribute name) to bypass live LDAP; the
        pure transform ConvertTo-EscTemplateObject is applied to each.
    .PARAMETER Server
        Optional DC/server to bind to.
    .PARAMETER ConfigurationNamingContext
        Optional config NC DN (auto-detected from RootDSE when omitted).
    .PARAMETER InputObject
        Optional array of raw property bags (offline mode).
    .PARAMETER ExtraLowPrivSid
        Optional extra low-priv SIDs forwarded to the ACL parser.
    .OUTPUTS
        [pscustomobject] Template[].
    .EXAMPLE
        Get-EscCertificateTemplate -Verbose
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string] $ConfigurationNamingContext,

        [Parameter(Mandatory = $false)]
        [object[]] $InputObject,

        [Parameter(Mandatory = $false)]
        [string[]] $ExtraLowPrivSid = @()
    )

    if ($PSBoundParameters.ContainsKey('InputObject') -and $null -ne $InputObject) {
        Write-EscLog -Component 'Templates' -Message ("Offline mode: transforming {0} fixture record(s)." -f @($InputObject).Count)
        $out = @()
        foreach ($rec in $InputObject) {
            $bag = $rec
            if ($rec -isnot [hashtable]) {
                if ($rec -is [System.DirectoryServices.SearchResult]) {
                    $bag = ConvertTo-EscPropertyBag -SearchResult $rec
                }
                else {
                    $bag = @{}
                    foreach ($p in $rec.PSObject.Properties) {
                        $bag[$p.Name.ToLowerInvariant()] = @($p.Value)
                    }
                }
            }
            $out += ConvertTo-EscTemplateObject -Property $bag -ExtraLowPrivSid $ExtraLowPrivSid
        }
        return @($out)
    }

    $configNc = $ConfigurationNamingContext
    if ([string]::IsNullOrWhiteSpace($configNc)) {
        $configNc = Get-EscConfigNamingContext -Server $Server
    }
    if ([string]::IsNullOrWhiteSpace($configNc)) {
        Write-EscLog -Component 'Templates' -Level Warning -Message 'Could not resolve configuration naming context; returning empty set.'
        return @()
    }

    $searchRoot = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f $configNc
    $props = @(
        'cn', 'name', 'displayName', 'msPKI-Cert-Template-OID', 'msPKI-Template-Schema-Version',
        'msPKI-Certificate-Name-Flag', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Application-Policy',
        'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'msPKI-RA-Application-Policies',
        'msPKI-Certificate-Policy', 'nTSecurityDescriptor', 'distinguishedName'
    )

    $results = Invoke-EscLdapSearch -SearchRoot $searchRoot -Filter '(objectClass=pKICertificateTemplate)' `
        -Server $Server -PropertiesToLoad $props -SearchScope 'OneLevel'

    Write-EscLog -Component 'Templates' -Message ("Retrieved {0} template object(s)." -f @($results).Count)

    $out = @()
    foreach ($r in $results) {
        try {
            $bag = ConvertTo-EscPropertyBag -SearchResult $r
            $out += ConvertTo-EscTemplateObject -Property $bag -ExtraLowPrivSid $ExtraLowPrivSid
        }
        catch {
            Write-EscLog -Component 'Templates' -Level Warning -Message ("Failed to map a template: {0}" -f $_.Exception.Message)
        }
    }
    return @($out)
}
