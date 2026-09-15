@echo off
title Lamsa | لمسة Open Banking Shield Launcher
echo ============================================================
echo  Starting Lamsa | لمسة Open Banking API Security Shield...
echo ============================================================

echo Launching FastAPI Backend on http://localhost:3000 ...
start "FinGuard Backend" cmd /k "python -m uvicorn backend.main:app --host 127.0.0.1 --port 3000 --reload"

timeout /t 3 >nul

echo Launching Streamlit Dashboard on http://localhost:8501 ...
start "FinGuard Dashboard" cmd /k "streamlit run dashboard/app.py --server.port 8501"

echo.
echo Both services launched successfully!
echo Backend API: http://localhost:3000
echo Streamlit Dashboard: http://localhost:8501
pause
