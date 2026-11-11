# Wait for a one-click Railway CLI login, then deploy AgentProof.cloud.
# Run: powershell -ExecutionPolicy Bypass -File scripts\deploy_railway.ps1
# The login step opens https://railway.com/activate and must be approved once by
# the account owner; everything after that is unattended.

$ErrorActionPreference = "Continue"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "waiting for Railway login (approve the activation link in the browser)"
$deadline = (Get-Date).AddMinutes(25)
while ((Get-Date) -lt $deadline) {
    $who = (railway whoami 2>&1 | Out-String)
    if ($who -notmatch "Unauthorized|not logged|Please login") { break }
    Start-Sleep -Seconds 5
}

Write-Host "=== whoami ==="
railway whoami 2>&1
if ((railway whoami 2>&1 | Out-String) -match "Unauthorized|Please login") {
    Write-Host "login not completed; aborting"
    exit 1
}

Write-Host "=== deploy (creates project + service on first run) ==="
railway up -y -d 2>&1

Start-Sleep -Seconds 10
Write-Host "=== status ==="
railway status --json 2>&1

Write-Host "=== volume ==="
railway volume add --mount-path /data --json 2>&1

Write-Host "=== redeploy with volume ==="
railway up -y -d 2>&1

Start-Sleep -Seconds 10
Write-Host "=== domain ==="
railway domain 2>&1

Write-Host "=== deployments ==="
railway deployment list --json 2>&1
