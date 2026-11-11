param(
    [int]$Port = 8791
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$env:AGENTPROOF_DATA_DIR = Join-Path $root "data"
Write-Host ""
Write-Host "  AgentProof.cloud" -ForegroundColor Cyan
Write-Host "  site + API   ->  http://127.0.0.1:$Port" -ForegroundColor Green
Write-Host "  health       ->  http://127.0.0.1:$Port/api/health" -ForegroundColor DarkGray
Write-Host "  data dir     ->  $env:AGENTPROOF_DATA_DIR" -ForegroundColor DarkGray
Write-Host ""

python -m uvicorn server.app:app --host 127.0.0.1 --port $Port --reload
