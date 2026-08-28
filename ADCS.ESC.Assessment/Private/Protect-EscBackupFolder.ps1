function Protect-EscBackupFolder {
    <#
    .SYNOPSIS
        Hardens a folder ACL to Administrators + SYSTEM only (removes inheritance).
    .DESCRIPTION
        Used on the CA_Backup folder, which can hold the exported private key (.p12).
        Replaces the DACL so only BUILTIN\Administrators and NT AUTHORITY\SYSTEM keep
        Full Control, and strips inherited ACEs, applied recursively to existing files.
        Only touches the tool's own output folder; never a CA or directory object.
        Returns $true on success, $false otherwise. Never throws.
    .PARAMETER Path
        Folder to harden.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path
    )

    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $false }
        $null = & icacls.exe $Path /inheritance:r `
            /grant:r 'BUILTIN\Administrators:(OI)(CI)F' `
            'NT AUTHORITY\SYSTEM:(OI)(CI)F' /T /C 2>&1
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        return $false
    }
}
