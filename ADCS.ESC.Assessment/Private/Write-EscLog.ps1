function Write-EscLog {
    <#
    .SYNOPSIS
        Simple logging wrapper for the ADCS.ESC.Assessment module.
    .DESCRIPTION
        Emits a component-tagged message through Write-Verbose (default) or
        Write-Warning. Purely a convenience wrapper so collectors/analyzers
        produce consistently tagged diagnostic output. Read-only; no side effects.
    .PARAMETER Component
        Short tag identifying the calling component (e.g. 'Templates', 'CAConfig').
    .PARAMETER Message
        The message text to emit.
    .PARAMETER Level
        'Verbose' (default) or 'Warning'.
    .EXAMPLE
        Write-EscLog -Component 'Templates' -Message 'Found 12 templates.'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Component,

        [Parameter(Mandatory = $true)]
        [string] $Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Verbose', 'Warning')]
        [string] $Level = 'Verbose'
    )

    $line = '[{0}] {1}' -f $Component, $Message
    if ($Level -eq 'Warning') {
        Write-Warning -Message $line
    }
    else {
        Write-Verbose -Message $line
    }
}
