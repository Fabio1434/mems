#!/usr/bin/env bash
# start_protection.sh
# Lance ai_engine.py en arrière-plan sur le routeur, avec logs et CSV de
# métriques (utile pour les benchmarks). À exécuter DANS le conteneur
# xdp-router (ou sur toute machine où bcc est installé).
#
# Usage :
#   ./start_protection.sh [fichier-config.yaml] [interface]
#
#   Si un fichier de config est fourni, l'interface qu'il contient est
#   utilisée sauf si explicitement précisée en second argument.
#   Sans fichier de config : ./start_protection.sh "" eth1
#
# Arrêt :
#   ./stop_protection.sh

set -euo pipefail

CONFIG_FILE="${1:-}"
IFACE="${2:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AI_ENGINE="$SCRIPT_DIR/../src/ai_engine.py"
LOG_FILE="/root/ai_engine.log"
CSV_FILE="/root/ai_engine_metrics.csv"
PID_FILE="/root/ai_engine.pid"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "ai_engine.py est déjà actif (PID $(cat "$PID_FILE"))."
    exit 0
fi

ARGS=(--log-csv "$CSV_FILE")
if [[ -n "$CONFIG_FILE" ]]; then
    ARGS+=(--config "$CONFIG_FILE")
    echo "[*] Démarrage de ai_engine.py avec la config $CONFIG_FILE..."
else
    if [[ -z "$IFACE" ]]; then
        echo "Usage: $0 [fichier-config.yaml] [interface]"
        echo "  (au moins l'un des deux doit être fourni)"
        exit 1
    fi
    ARGS+=(--iface "$IFACE")
    echo "[*] Démarrage de ai_engine.py sur l'interface $IFACE (sans fichier de config)..."
fi

nohup python3 "$AI_ENGINE" "${ARGS[@]}" > "$LOG_FILE" 2>&1 &

echo $! > "$PID_FILE"
sleep 2

if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "[*] Protection active (PID $(cat "$PID_FILE"))."
    echo "    Logs   : $LOG_FILE"
    echo "    Métriques CSV : $CSV_FILE"
    echo "    Dashboard temps réel : http://<ip-de-ce-conteneur>:8080"
    if [[ -n "$CONFIG_FILE" ]] && grep -q "dry_run: *true" "$CONFIG_FILE" 2>/dev/null; then
        echo "    ⚠️  MODE SIMULATION ACTIF (dry_run: true dans $CONFIG_FILE) -- aucun blocage réel."
    fi
else
    echo "[!] Échec du démarrage -- voir $LOG_FILE"
    cat "$LOG_FILE"
    exit 1
fi
