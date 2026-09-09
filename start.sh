#!/usr/bin/env bash
# One-command local startup for the AI Agent Security Monitor.
#
# Sets up (if needed) and launches:
#   - the FastAPI backend on http://127.0.0.1:8000
#   - the Vite/React frontend on http://127.0.0.1:5173
#
# Usage:
#   ./start.sh
#
# Stop with Ctrl+C (both processes are cleaned up on exit).

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"

echo "=== AI Agent Security Monitor: startup ==="

# ---------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------
cd "$BACKEND_DIR"

if [ ! -d "venv" ]; then
  echo "[backend] Creating virtual environment..."
  python3 -m venv venv
fi

echo "[backend] Installing/checking Python dependencies..."
# shellcheck disable=SC1091
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

if [ ! -f "data/security_prompts.csv" ]; then
  echo "[backend] Building security_prompts.csv dataset..."
  python scripts/build_dataset.py
fi

if [ ! -f "models/isolation_forest.joblib" ]; then
  echo "[backend] Training the behavioral anomaly model (Isolation Forest, ~5s)..."
  python train_model.py --n-samples 2000 --contamination 0.05 --seed 42
  echo "[backend] Evaluating it on held-out synthetic sessions..."
  python evaluate_model.py --n-normal 400 --n-abnormal 400 --seed 1337
fi

echo "[backend] Starting FastAPI (uvicorn) on http://127.0.0.1:8000 ..."
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload > "$ROOT_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
deactivate

cleanup() {
  echo ""
  echo "Shutting down..."
  kill "$BACKEND_PID" 2>/dev/null || true
  kill "$FRONTEND_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for backend health check
echo "[backend] Waiting for backend to become healthy..."
for i in $(seq 1 30); do
  if curl -s http://127.0.0.1:8000/api/health > /dev/null 2>&1; then
    echo "[backend] Ready."
    break
  fi
  sleep 1
done

# ---------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------
cd "$FRONTEND_DIR"

if [ ! -d "node_modules" ]; then
  echo "[frontend] Installing npm dependencies (this can take a minute)..."
  npm install
fi

echo "[frontend] Starting Vite dev server on http://127.0.0.1:5173 ..."
npm run dev -- --host 127.0.0.1 --port 5173 > "$ROOT_DIR/frontend.log" 2>&1 &
FRONTEND_PID=$!

echo ""
echo "=================================================================="
echo " AI Agent Security Monitor is starting up:"
echo "   Frontend:  http://127.0.0.1:5173"
echo "   Backend:   http://127.0.0.1:8000"
echo "   API docs:  http://127.0.0.1:8000/docs"
echo ""
echo " Logs: backend.log / frontend.log (in this directory)"
echo " Press Ctrl+C to stop both servers."
echo "=================================================================="

wait
