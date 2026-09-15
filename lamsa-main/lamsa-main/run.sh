#!/usr/bin/env bash
# Lamsa | لمسة Single Execution Launcher Script
echo "============================================================"
echo " Starting Lamsa | لمسة Open Banking API Security Shield...  "
echo "============================================================"

# Launch FastAPI backend in background
python -m uvicorn backend.main:app --host 127.0.0.1 --port 3000 --reload &
BACKEND_PID=$!

sleep 2

# Launch Streamlit dashboard in foreground
streamlit run dashboard/app.py --server.port 8501

# Cleanup backend process on exit
kill $BACKEND_PID
