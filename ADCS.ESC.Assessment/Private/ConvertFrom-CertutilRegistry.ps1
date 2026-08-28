function ConvertFrom-CertutilRegistry {
    <#
    .SYNOPSIS
        Parses the text output of `certutil -getreg <value>` into a typed value.
    .DESCRIPTION
        Pure text transform (no external calls) so it is unit-testable with fixture
        strings. Handles the common REG types produced by certutil:
          - REG_DWORD / REG_QWORD  -> [long] (hex form preferred)
          - REG_MULTI_SZ           -> [string[]]
          - REG_SZ                 -> [string]
          - REG_BINARY             -> [byte[]] (hex bytes reassembled)
        Returns $null when no value could be parsed.
    .PARAMETER Text
        The raw stdout captured from certutil -getreg.
    .PARAMETER ValueName
        The registry value name that was requested (used to anchor the parse).
    .OUTPUTS
        [long] | [string[]] | [string] | [byte[]] | $null
    .EXAMPLE
        ConvertFrom-CertutilRegistry -Text $out -ValueName 'EditFlags'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Text,

        [Parameter(Mandatory = $true)]
        [string] $ValueName
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $lines = $Text -split "`r?`n"

    $leaf = $ValueName
    if ($ValueName.Contains('\')) {
        $leaf = $ValueName.Substring($ValueName.LastIndexOf('\') + 1)
    }
    $escLeaf = [regex]::Escape($leaf)

    foreach ($line in $lines) {
        $m = [regex]::Match($line, ('^\s*' + $escLeaf + '\s+REG_(DWORD|QWORD)\s*=\s*([0-9a-fA-F]+)\b'))
        if ($m.Success) {
            $hex = $m.Groups[2].Value
            try {
                return [System.Convert]::ToInt64($hex, 16)
            }
            catch {
                $dm = [regex]::Match($line, '\((\d+)\)')
                if ($dm.Success) { return [long] $dm.Groups[1].Value }
                return $null
            }
        }
    }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $m = [regex]::Match($lines[$i], ('^\s*' + $escLeaf + '\s+REG_MULTI_SZ\s*='))
        if ($m.Success) {
            $items = New-Object System.Collections.ArrayList
            for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                $ln = $lines[$j]
                if ([string]::IsNullOrWhiteSpace($ln)) { break }
                if ($ln -match 'REG_[A-Z_]+\s*=') { break }
                $im = [regex]::Match($ln, '^\s*\d+:\s*(.+?)\s*$')
                if ($im.Success) {
                    [void]$items.Add($im.Groups[1].Value.Trim())
                }
                else {
                    $trim = $ln.Trim()
                    if (-not [string]::IsNullOrWhiteSpace($trim)) { [void]$items.Add($trim) }
                }
            }
            return @($items.ToArray())
        }
    }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $m = [regex]::Match($lines[$i], ('^\s*' + $escLeaf + '\s+REG_BINARY\s*='))
        if ($m.Success) {
            $bytes = New-Object System.Collections.ArrayList
            $started = $false
            for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                $ln = $lines[$j]
                if ([string]::IsNullOrWhiteSpace($ln)) { continue }
                if ($ln -match 'REG_[A-Z_]+\s*=') { break }
                $bm = [regex]::Match($ln, '^\s*[0-9a-fA-F]{4}\s+((?:[0-9a-fA-F]{2}\s*){1,16})')
                if ($bm.Success) {
                    $started = $true
                    $hexBytes = [regex]::Matches($bm.Groups[1].Value, '[0-9a-fA-F]{2}')
                    foreach ($hb in $hexBytes) {
                        [void]$bytes.Add([System.Convert]::ToByte($hb.Value, 16))
                    }
                }
                elseif ($started) {
                    break
                }
            }
            if ($bytes.Count -gt 0) {
                return [byte[]] $bytes.ToArray()
            }
            return $null
        }
    }

    foreach ($line in $lines) {
        $m = [regex]::Match($line, ('^\s*' + $escLeaf + '\s+REG_SZ\s*=\s*(.+?)\s*$'))
        if ($m.Success) {
            return [string] $m.Groups[1].Value
        }
    }

    return $null
}
