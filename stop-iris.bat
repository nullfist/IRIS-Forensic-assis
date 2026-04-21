@echo off
title IRIS DFIR Platform - Shutdown
color 0C

echo ============================================
echo    IRIS - Incident Reconstruction & Intelligence System
echo    Shutting down...
echo ============================================
echo.

REM Check if Docker is running
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not running.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

echo Stopping all IRIS containers...
docker-compose down

echo.
echo ============================================
echo    IRIS Platform has been stopped.
echo ============================================
echo.
echo    To start again, double-click start-iris.bat
echo.

pause