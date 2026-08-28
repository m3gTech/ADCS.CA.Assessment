function ConvertTo-EscPropertyBag {
    <#
    .SYNOPSIS
        Normalizes a DirectoryServices SearchResult into a plain hashtable.
    .DESCRIPTION
        Converts a [System.DirectoryServices.SearchResult] (or its .Properties
        ResultPropertyCollection) into a hashtable of lowercased attribute name ->
        array of values, so the pure transform functions can consume it uniformly
        (and so fixtures can mimic the same shape). Read-only.
    .PARAMETER SearchResult
        A SearchResult or a ResultPropertyCollection.
    .OUTPUTS
        [hashtable]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object] $SearchResult
    )

    $bag = @{}
    $props = $null
    if ($SearchResult -is [System.DirectoryServices.SearchResult]) {
        $props = $SearchResult.Properties
    }
    else {
        $props = $SearchResult
    }

    if ($null -eq $props) { return $bag }

    foreach ($name in $props.PropertyNames) {
        $values = New-Object System.Collections.ArrayList
        foreach ($v in $props[$name]) {
            [void]$values.Add($v)
        }
        $bag[([string]$name).ToLowerInvariant()] = $values.ToArray()
    }
    return $bag
}
