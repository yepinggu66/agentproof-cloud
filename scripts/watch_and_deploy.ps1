# Wait until the Railway plan is active, create the project non-interactively,
# then deploy. Start it, finish the subscription page in the browser, and no
# further CLI clicks are needed.
$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$deadline = (Get-Date).AddMinutes(25)
$created = $false
while ((Get-Date) -lt $deadline) {
    $out = (railway init --name agentproof-cloud --workspace yepinggu --json 2>&1 | Out-String)
    Write-Host $out
    if ($LASTEXITCODE -eq 0 -and $out -notmatch "trial|expired|select a plan") {
        $created = $true
        break
    }
    Start-Sleep -Seconds 25
}

if (-not $created) {
    Write-Host "plan still inactive; giving up"
    exit 1
}

Write-Host "=== deploy ==="
railway up -y -d 2>&1
Start-Sleep -Seconds 10
Write-Host "=== volume ==="
railway volume add --mount-path /data --json 2>&1
Write-Host "=== redeploy with volume ==="
railway up -y -d 2>&1
Start-Sleep -Seconds 10
Write-Host "=== domain ==="
railway domain 2>&1
Write-Host "=== status ==="
railway status --json 2>&1
