#!/usr/bin/env bash
# start_protection.sh
# Lance ai_engine.py en arrière-plan sur le routeur, avec logs et CSV de
# métriques (utile pour les benchmarks). À exécuter DANS le conteneur
# xdp-router (ou sur toute machine où bcc est installé).
#
# Usage :
#   ./start_protection.sh [interface]   (défaut: eth1)
#
# Arrêt :
#   ./stop_protection.sh

set -euo pipefail

IFACE="${1:-eth1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AI_ENGINE="$SCRIPT_DIR/../src/ai_engine.py"
LOG_FILE="/root/ai_engine.log"
CSV_FILE="/root/ai_engine_metrics.csv"
PID_FILE="/root/ai_engine.pid"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "ai_engine.py est déjà actif (PID $(cat "$PID_FILE"))."
    exit 0
fi

echo "[*] Démarrage de ai_engine.py sur l'interface $IFACE..."
nohup python3 "$AI_ENGINE" --iface "$IFACE" --log-csv "$CSV_FILE" \
    > "$LOG_FILE" 2>&1 &

echo $! > "$PID_FILE"
sleep 2

if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "[*] Protection active (PID $(cat "$PID_FILE"))."
    echo "    Logs   : $LOG_FILE"
    echo "    Métriques CSV : $CSV_FILE"
else
    echo "[!] Échec du démarrage -- voir $LOG_FILE"
    cat "$LOG_FILE"
    exit 1
fi
