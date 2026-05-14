Write-Host "=========================================="
Write-Host "    Installing AEGIS Security Platform   "
Write-Host "=========================================="

Write-Host "[+] Verifying dependencies..."
if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
    Write-Error "[-] Docker is required but not installed. Please install Docker Desktop first."
    exit 1
}

Write-Host "[+] Building AEGIS containers..."
docker-compose build

Write-Host "[+] Starting AEGIS securely..."
docker-compose up -d

Write-Host "[+] Installing Python dependencies for AEGIS Guardian..."
$pythonVenv = "python\aegis-ai\.venv\Scripts\python.exe"
if (Test-Path $pythonVenv) {
    & $pythonVenv -m pip install win11toast websockets --quiet
    Write-Host "[+] AEGIS Guardian dependencies installed."
} else {
    Write-Host "[!] Virtual env not found. Run: cd python\aegis-ai && python -m venv .venv && .venv\Scripts\pip install -r requirements.txt"
}

Write-Host "[+] Registering AEGIS Guardian as a background task..."
$guardianPath = (Resolve-Path "python\aegis-ai\aegis_guardian.py").Path
$pythonExe    = (Resolve-Path $pythonVenv).Path
$action       = New-ScheduledTaskAction -Execute $pythonExe -Argument "`"$guardianPath`""
$trigger      = New-ScheduledTaskTrigger -AtLogOn
$settings     = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal    = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName "AEGIS Guardian" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Write-Host "[+] AEGIS Guardian registered — will auto-start at next login."

Write-Host "[+] Starting AEGIS Guardian now..."
Start-Process -FilePath $pythonExe -ArgumentList "`"$guardianPath`"" -WindowStyle Hidden

Write-Host "=========================================="
Write-Host " AEGIS is now running."
Write-Host " Dashboard: http://localhost:5173"
Write-Host " API:       http://localhost:8000"
Write-Host " Guardian:  Running in background (notifications active)"
Write-Host "=========================================="
