$ErrorActionPreference = 'Stop'

$folders = 'Private', 'Collectors', 'Scoring', 'Analyzers', 'Reporting', 'Public'
foreach ($folder in $folders) {
    $path = Join-Path -Path $PSScriptRoot -ChildPath $folder
    if (Test-Path -Path $path) {
        Get-ChildItem -Path $path -Filter '*.ps1' -File -Recurse |
            Sort-Object -Property Name |
            ForEach-Object {
                . $_.FullName
            }
    }
}

Export-ModuleMember -Function 'Invoke-ESCAssessment', 'Export-EscCaData'
