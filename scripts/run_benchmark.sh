#!/usr/bin/env bash
# run_benchmark.sh
# Orchestration du benchmark de performance : compare le comportement du lab
# SANS protection (baseline) et AVEC le filtre XDP/IA actif (protected)
# lors d'une attaque DDoS simulée.
#
# Usage :
#   ./run_benchmark.sh baseline     # routeur en simple forwarding, sans XDP/IA
#   ./run_benchmark.sh protected    # ai_engine.py actif sur le routeur (XDP + IA)
#
# Résultats écrits dans ./benchmark_results/<mode>/
#   - cpu.csv        : occupation CPU du routeur au fil du temps (docker stats)
#   - latency.csv     : RTT (ms) mesuré depuis legit-client vers target-server
#   - traffic_summary.txt : paquets envoyés par l'attaquant vs reçus par la cible
#
# Prérequis : lab déjà déployé avec `containerlab deploy -t topology.clab.yaml`

set -euo pipefail

MODE="${1:-}"
if [[ "$MODE" != "baseline" && "$MODE" != "protected" ]]; then
    echo "Usage: $0 [baseline|protected]"
    exit 1
fi

LAB_PREFIX="clab-xdp-ai-lab"
ROUTER="${LAB_PREFIX}-xdp-router"
ATTACKER="${LAB_PREFIX}-attacker"
LEGIT_CLIENT="${LAB_PREFIX}-legit-client"
TARGET="${LAB_PREFIX}-target-server"

TARGET_IP="10.0.3.2"
ATTACK_DURATION=30       # secondes
CPU_SAMPLE_INTERVAL=1    # secondes

OUT_DIR="./benchmark_results/${MODE}"
mkdir -p "$OUT_DIR"

echo "=== Benchmark en mode : $MODE ==="

# ------------------------------------------------------------------
# 1. (Re)démarrer ai_engine.py sur le routeur si mode = protected
# ------------------------------------------------------------------
if [[ "$MODE" == "protected" ]]; then
    echo "[*] Démarrage de ai_engine.py (XDP + IA multi-critères) sur le routeur..."
    docker exec -d "$ROUTER" bash -c \
        "pkill -f ai_engine.py || true; sleep 1; python3 /root/ai_engine.py --iface eth1 --log-csv /root/ai_engine_metrics.csv > /root/ai_engine.log 2>&1 &"
    sleep 3  # laisser le temps au programme XDP de s'attacher
else
    echo "[*] Mode baseline : on s'assure que ai_engine.py n'est PAS actif."
    docker exec "$ROUTER" bash -c "pkill -f ai_engine.py || true"
    docker exec "$ROUTER" ip link set dev eth1 xdp off || true
    sleep 1
fi

# ------------------------------------------------------------------
# 2. Lancer la capture CPU du routeur en arrière-plan
# ------------------------------------------------------------------
echo "timestamp,cpu_percent" > "$OUT_DIR/cpu.csv"
(
    END=$((SECONDS + ATTACK_DURATION + 10))
    while [[ $SECONDS -lt $END ]]; do
        CPU=$(docker stats "$ROUTER" --no-stream --format "{{.CPUPerc}}" | tr -d '%')
        echo "$(date +%s.%N),$CPU" >> "$OUT_DIR/cpu.csv"
        sleep "$CPU_SAMPLE_INTERVAL"
    done
) &
CPU_MONITOR_PID=$!

# ------------------------------------------------------------------
# 3. Lancer le trafic légitime en continu (iperf3) en arrière-plan
# ------------------------------------------------------------------
echo "[*] Démarrage du serveur iperf3 sur target-server..."
docker exec -d "$TARGET" iperf3 -s -1 || true
sleep 1

echo "[*] Démarrage du trafic légitime (iperf3 client) depuis legit-client..."
docker exec -d "$LEGIT_CLIENT" bash -c \
    "iperf3 -c $TARGET_IP -t $ATTACK_DURATION > /root/iperf_client.log 2>&1"

# ------------------------------------------------------------------
# 4. Mesurer la latence en continu (ping) depuis legit-client
# ------------------------------------------------------------------
echo "[*] Mesure de la latence (ping) en parallèle..."
docker exec "$LEGIT_CLIENT" bash -c \
    "ping -i 1 -w $ATTACK_DURATION $TARGET_IP" \
    | grep --line-buffered "time=" \
    | sed -E 's/.*time=([0-9.]+).*/\1/' \
    > "$OUT_DIR/latency_raw.txt" &
PING_PID=$!

# ------------------------------------------------------------------
# 5. Lancer l'attaque DDoS (hping3 SYN flood) depuis attacker
# ------------------------------------------------------------------
echo "[*] Lancement de l'attaque SYN flood (hping3) pendant ${ATTACK_DURATION}s..."
docker exec "$ATTACKER" bash -c \
    "hping3 -S -p 80 --flood $TARGET_IP -c 200000" \
    > "$OUT_DIR/hping3_attacker.log" 2>&1 || true

# ------------------------------------------------------------------
# 6. Attendre la fin des mesures en arrière-plan
# ------------------------------------------------------------------
wait "$PING_PID" 2>/dev/null || true
wait "$CPU_MONITOR_PID" 2>/dev/null || true

# ------------------------------------------------------------------
# 7. Compter les paquets reçus côté cible pendant la fenêtre d'attaque
#    (approxime le nombre de paquets NON bloqués par le filtre XDP)
# ------------------------------------------------------------------
echo "[*] Comptage des paquets reçus côté target-server (tcpdump, 5s)..."
RECEIVED_COUNT=$(docker exec "$TARGET" timeout 5 tcpdump -i eth1 -c 100000 -nn "src host $(docker exec $ATTACKER hostname -i)" 2>/dev/null | wc -l || echo "0")

SENT_COUNT=$(grep -oE "[0-9]+ packets transmitted" "$OUT_DIR/hping3_attacker.log" | awk '{print $1}' || echo "unknown")

{
    echo "Mode: $MODE"
    echo "Paquets envoyés par l'attaquant (hping3): $SENT_COUNT"
    echo "Paquets reçus côté target-server (échantillon 5s): $RECEIVED_COUNT"
    echo "NB: en mode 'protected', un écart important entre envoyés et reçus"
    echo "    indique que le filtre XDP a bien absorbé l'attaque."
} > "$OUT_DIR/traffic_summary.txt"

# ------------------------------------------------------------------
# 8. Reformater la latence en CSV exploitable
# ------------------------------------------------------------------
echo "sample,latency_ms" > "$OUT_DIR/latency.csv"
awk '{print NR","$0}' "$OUT_DIR/latency_raw.txt" >> "$OUT_DIR/latency.csv"
rm -f "$OUT_DIR/latency_raw.txt"

# ------------------------------------------------------------------
# 9. Récupérer les métriques précises de ai_engine.py (mode protected)
# ------------------------------------------------------------------
if [[ "$MODE" == "protected" ]]; then
    docker cp "${ROUTER}:/root/ai_engine_metrics.csv" "$OUT_DIR/ai_engine_metrics.csv" 2>/dev/null || \
        echo "[!] Impossible de récupérer ai_engine_metrics.csv (le fichier existe-t-il sur le routeur ?)"
fi

echo "=== Benchmark '$MODE' terminé. Résultats dans $OUT_DIR/ ==="
cat "$OUT_DIR/traffic_summary.txt"
