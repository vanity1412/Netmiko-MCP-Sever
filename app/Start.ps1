param(
    [ValidateSet('Web', 'Terminal', 'Check')]
    [string]$Mode = 'Web'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root
$env:XDG_DATA_HOME = Join-Path $root 'runtime\data'
$env:XDG_CONFIG_HOME = Join-Path $root 'runtime\settings'
$env:XDG_CACHE_HOME = Join-Path $root 'runtime\cache'
$env:XDG_STATE_HOME = Join-Path $root 'runtime\state'
$env:NETWORK_MCP_DATA_DIR = Join-Path $root 'runtime\data\netmiko'
$env:OPENCODE_CONFIG = Join-Path $root 'opencode.json'
foreach ($dir in @($env:XDG_DATA_HOME, $env:XDG_CONFIG_HOME, $env:XDG_CACHE_HOME, $env:XDG_STATE_HOME, $env:NETWORK_MCP_DATA_DIR)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
$exe = Join-Path $PSScriptRoot 'opencode.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw 'Missing app\opencode.exe.' }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'Python is required. Install Python and Netmiko first.' }
if ($Mode -eq 'Check') {
    & python -u (Join-Path $root 'mcp\check.py')
    exit $LASTEXITCODE
}
if ($Mode -eq 'Terminal') {
    & $exe --standalone
    exit $LASTEXITCODE
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = $listener.LocalEndpoint.Port
$listener.Stop()
$url = "http://127.0.0.1:$port"
$server = Start-Process -FilePath $exe -ArgumentList @('serve', '--hostname', '127.0.0.1', '--port', "$port") -WorkingDirectory $root -NoNewWindow -PassThru
try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($server.HasExited) { throw "OpenCode server exited with code $($server.ExitCode)." }
        try {
            $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) { $ready = $true; break }
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ready) { throw 'OpenCode Web did not become ready.' }
    Write-Host "Workspace: $root"
    Write-Host "OpenCode Web: $url"
    Start-Process $url
    Write-Host 'Keep this window open. Close it or press Ctrl+C when finished.'
    $server.WaitForExit()
    exit $server.ExitCode
} finally {
    if (-not $server.HasExited) { Stop-Process -Id $server.Id }
}
