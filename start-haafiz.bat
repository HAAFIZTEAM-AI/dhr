@echo off
REM ============================================================
REM  HAAFIZ - One-click Start Script
REM  Place this file inside the "Grand Final v5.0" folder
REM  (same level as the ai-service, backend, and frontend folders)
REM  Then just double-click it to start everything.
REM ============================================================

set BASE=%~dp0

echo Starting AI Service (port 5001)...
start "HAAFIZ - AI Service" cmd /k "cd /d "%BASE%ai-service" && call venv\Scripts\activate && python app.py"

timeout /t 3 /nobreak >nul

echo Starting Backend (port 3001)...
start "HAAFIZ - Backend" cmd /k "cd /d "%BASE%backend" && npm start"

timeout /t 3 /nobreak >nul

echo Starting Frontend...
start "HAAFIZ - Frontend" cmd /k "cd /d "%BASE%frontend" && npm run dev"

echo.
echo All three services are starting in separate windows:
echo   1. AI Service  - http://localhost:5001
echo   2. Backend     - http://localhost:3001
echo   3. Frontend    - check that window for the local URL (usually http://localhost:5173)
echo.
echo Keep all three windows open while you use the app.
echo Close this window any time - it is not needed once the others have opened.
pause
