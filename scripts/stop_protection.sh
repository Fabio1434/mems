#!/usr/bin/env bash
# stop_protection.sh
# Arrête proprement ai_engine.py (déclenche le détachement du programme XDP
# via son handler SIGINT/finally).

set -euo pipefail

PID_FILE="/root/ai_engine.pid"

if [[ ! -f "$PID_FILE" ]]; then
    echo "Aucun ai_engine.py actif (PID file introuvable)."
    exit 0
fi

PID="$(cat "$PID_FILE")"
if kill -0 "$PID" 2>/dev/null; then
    echo "[*] Arrêt de ai_engine.py (PID $PID)..."
    kill -INT "$PID"
    sleep 2
    echo "[*] Arrêté."
else
    echo "Le processus $PID n'est plus actif."
fi

rm -f "$PID_FILE"
