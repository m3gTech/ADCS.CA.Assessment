function Read-EscRegKey {
    <#
    .SYNOPSIS
        Recursively reads a RegistryKey into an ordered hashtable (read-only helper).
    .DESCRIPTION
        Internal helper for ConvertTo-EscRegistryDump. Captures each value's name,
        kind, and data (binary rendered as hex; env strings left un-expanded) plus
        every sub-key, bounded by MaxDepth. Never writes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $Key,

        [Parameter(Mandatory = $false)]
        [int] $Depth = 0,

        [Parameter(Mandatory = $false)]
        [int] $MaxDepth = 20
    )

    $node = [ordered]@{ '(values)' = [ordered]@{} }

    foreach ($vn in $Key.GetValueNames()) {
        $kind = $Key.GetValueKind($vn)
        $val = $Key.GetValue($vn, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($val -is [byte[]]) { $val = ([System.BitConverter]::ToString([byte[]]$val)) -replace '-', '' }
        $name = $vn
        if ([string]::IsNullOrEmpty($name)) { $name = '(default)' }
        $node['(values)'][$name] = [ordered]@{ Type = [string]$kind; Data = $val }
    }

    if ($Depth -lt $MaxDepth) {
        foreach ($sn in $Key.GetSubKeyNames()) {
            $sub = $null
            try { $sub = $Key.OpenSubKey($sn) } catch { $sub = $null }
            if ($null -ne $sub) {
                $node[$sn] = Read-EscRegKey -Key $sub -Depth ($Depth + 1) -MaxDepth $MaxDepth
                try { $sub.Close() } catch { }
            }
        }
    }

    return $node
}

function ConvertTo-EscRegistryDump {
    <#
    .SYNOPSIS
        Reads a remote HKLM sub-tree into a nested object (read-only, live).
    .DESCRIPTION
        Opens the remote machine's HKEY_LOCAL_MACHINE hive over the read-only
        remote-registry API and returns the requested sub-key as a nested ordered
        hashtable (values + sub-keys). Used to export a CA's CertSvc\Configuration
        sub-tree when the tool runs off-box. Requires the Remote Registry service
        and appropriate read rights; never modifies the registry.
    .PARAMETER ComputerName
        Target host holding the CA.
    .PARAMETER SubKey
        HKLM sub-key path (e.g. SYSTEM\CurrentControlSet\Services\CertSvc\Configuration).
    .PARAMETER MaxDepth
        Recursion bound (default 20).
    .OUTPUTS
        [System.Collections.Specialized.OrderedDictionary]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $ComputerName,

        [Parameter(Mandatory = $true)]
        [string] $SubKey,

        [Parameter(Mandatory = $false)]
        [int] $MaxDepth = 20
    )

    $base = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
        $root = $base.OpenSubKey($SubKey)
        if ($null -eq $root) { throw ("Sub-key not found: {0}" -f $SubKey) }
        $result = Read-EscRegKey -Key $root -Depth 0 -MaxDepth $MaxDepth
        try { $root.Close() } catch { }
        return $result
    }
    finally {
        if ($null -ne $base) { try { $base.Close() } catch { } }
    }
}
