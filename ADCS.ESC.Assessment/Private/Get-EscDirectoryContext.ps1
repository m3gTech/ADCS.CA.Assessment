function Get-EscConfigNamingContext {
    <#
    .SYNOPSIS
        Returns the Configuration naming context DN from RootDSE (read-only).
    .DESCRIPTION
        Binds to LDAP://<Server>/RootDSE and reads configurationNamingContext.
        Returns $null on failure (never throws).
    .PARAMETER Server
        Optional domain controller / server name. Default: current domain.
    .OUTPUTS
        System.String (config NC DN) or $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Server
    )

    $path = 'LDAP://RootDSE'
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $path = 'LDAP://{0}/RootDSE' -f $Server
    }

    $root = $null
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry($path)
        $configNc = [string] $root.Properties['configurationNamingContext'].Value
        if ([string]::IsNullOrWhiteSpace($configNc)) {
            return $null
        }
        return $configNc
    }
    catch {
        Write-EscLog -Component 'Directory' -Level Warning -Message ("Failed to read RootDSE: {0}" -f $_.Exception.Message)
        return $null
    }
    finally {
        if ($null -ne $root) { try { $root.Dispose() } catch { } }
    }
}

function Get-EscDefaultNamingContext {
    <#
    .SYNOPSIS
        Returns the Default (domain) naming context DN from RootDSE (read-only).
    .DESCRIPTION
        Binds to LDAP://<Server>/RootDSE and reads defaultNamingContext.
        Returns $null on failure (never throws).
    .PARAMETER Server
        Optional server name. Default: current domain.
    .OUTPUTS
        System.String or $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [string] $Server
    )

    $path = 'LDAP://RootDSE'
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $path = 'LDAP://{0}/RootDSE' -f $Server
    }

    $root = $null
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry($path)
        $dnc = [string] $root.Properties['defaultNamingContext'].Value
        if ([string]::IsNullOrWhiteSpace($dnc)) { return $null }
        return $dnc
    }
    catch {
        Write-EscLog -Component 'Directory' -Level Warning -Message ("Failed to read RootDSE defaultNamingContext: {0}" -f $_.Exception.Message)
        return $null
    }
    finally {
        if ($null -ne $root) { try { $root.Dispose() } catch { } }
    }
}

function Invoke-EscLdapSearch {
    <#
    .SYNOPSIS
        Runs a read-only LDAP subtree search and returns SearchResult objects.
    .DESCRIPTION
        Thin, safe wrapper around System.DirectoryServices.DirectorySearcher.
        Read-only (search only). Returns an empty array on any failure.
    .PARAMETER SearchRoot
        Distinguished name of the container to search under.
    .PARAMETER Filter
        LDAP filter (default '(objectClass=*)').
    .PARAMETER Server
        Optional server / DC to bind to.
    .PARAMETER PropertiesToLoad
        Optional list of attributes to load. Empty = all.
    .PARAMETER SearchScope
        'Base', 'OneLevel', or 'Subtree' (default 'Subtree').
    .OUTPUTS
        System.DirectoryServices.SearchResult[] (possibly empty).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $SearchRoot,

        [Parameter(Mandatory = $false)]
        [string] $Filter = '(objectClass=*)',

        [Parameter(Mandatory = $false)]
        [string] $Server,

        [Parameter(Mandatory = $false)]
        [string[]] $PropertiesToLoad = @(),

        [Parameter(Mandatory = $false)]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string] $SearchScope = 'Subtree'
    )

    $prefix = 'LDAP://'
    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $prefix = 'LDAP://{0}/' -f $Server
    }
    $path = '{0}{1}' -f $prefix, $SearchRoot

    $entry = $null
    $searcher = $null
    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry($path)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter = $Filter
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::$SearchScope
        $searcher.PageSize = 1000
        try {
            $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor `
                                      [System.DirectoryServices.SecurityMasks]::Owner -bor `
                                      [System.DirectoryServices.SecurityMasks]::Group
        }
        catch { }

        foreach ($p in $PropertiesToLoad) {
            if (-not [string]::IsNullOrWhiteSpace($p)) {
                [void]$searcher.PropertiesToLoad.Add($p)
            }
        }

        $found = $searcher.FindAll()
        $list = @()
        foreach ($r in $found) { $list += $r }
        return @($list)
    }
    catch {
        Write-EscLog -Component 'Directory' -Level Warning -Message ("LDAP search failed under '{0}': {1}" -f $SearchRoot, $_.Exception.Message)
        return @()
    }
    finally {
        if ($null -ne $searcher) { try { $searcher.Dispose() } catch { } }
        if ($null -ne $entry) { try { $entry.Dispose() } catch { } }
    }
}
