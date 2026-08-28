function Test-EscTcpPort {
    <#
    .SYNOPSIS
        Read-only TCP reachability probe (connect-only, never sends payload).
    .DESCRIPTION
        Attempts a bounded TCP connect to <ComputerName>:<Port> and returns $true
        if the port accepts the connection within TimeoutMs. Purely passive: it
        opens and immediately closes the socket. Never throws.
    .PARAMETER ComputerName
        Target host (DNS name or IP).
    .PARAMETER Port
        TCP port to probe (e.g. 135 for the RPC endpoint mapper).
    .PARAMETER TimeoutMs
        Connect timeout in milliseconds (default 1500).
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $ComputerName,

        [Parameter(Mandatory = $true)]
        [int] $Port,

        [Parameter(Mandatory = $false)]
        [int] $TimeoutMs = 1500
    )

    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($ComputerName, $Port, $null, $null)
        $done = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($done -and $client.Connected) {
            $client.EndConnect($iar)
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $client) { try { $client.Close() } catch { } }
    }
}
