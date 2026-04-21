@echo off
title IRIS DFIR Platform
color 0A

echo ============================================
echo    IRIS - Incident Reconstruction ^& Intelligence System
echo ============================================
echo.

docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not running. Start Docker Desktop first.
    pause >nul
    exit /b 1
)

echo [1/5] Stopping any existing containers...
docker-compose down >nul 2>&1

echo [2/5] Building and starting all services...
start "IRIS Services" cmd /k "docker-compose up --build"

echo [3/5] Waiting for backend to be ready (this takes 2-3 min on first run)...
:wait_backend
timeout /t 6 /nobreak >nul
curl -sf http://localhost:8000/health >nul 2>&1
if %errorlevel% neq 0 (
    echo       Still waiting...
    goto wait_backend
)
echo       Backend ready!

echo [4/5] Loading demo attack scenario...
timeout /t 2 /nobreak >nul

REM Build the ingest payload from the scenario JSONL file using PowerShell
powershell -NoProfile -Command ^
  "$records = Get-Content 'data\scenarios\phishing_to_exfiltration.jsonl' | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_ | ConvertFrom-Json }; " ^
  "$payload = @{ investigation_id = 'demo-attack-001'; enrich_graph = $true; artifacts = @(@{ source = 'sysmon'; artifact_name = 'phishing_to_exfiltration.jsonl'; records = $records }) }; " ^
  "$json = $payload | ConvertTo-Json -Depth 20 -Compress; " ^
  "Invoke-RestMethod -Uri 'http://localhost:8000/api/v1/ingest' -Method POST -ContentType 'application/json' -Body $json | ConvertTo-Json" ^
  2>nul

if %errorlevel% neq 0 (
    echo       [WARN] Demo data load failed - you can upload files manually via the UI.
) else (
    echo       Demo scenario loaded! Investigation ID: demo-attack-001
)

echo [5/5] Opening IRIS...
timeout /t 2 /nobreak >nul
start http://localhost:3000

echo.
echo ============================================
echo    IRIS is running!
echo ============================================
echo.
echo    Web Interface : http://localhost:3000
echo    API Docs      : http://localhost:8000/docs
echo    Neo4j Browser : http://localhost:7474  (neo4j / irispassword)
echo.
echo    To stop: run stop-iris.bat or docker-compose down
echo.
pause
