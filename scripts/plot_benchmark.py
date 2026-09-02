#!/usr/bin/env python3
"""
plot_benchmark.py
Génère les graphiques comparatifs (baseline vs protected) à partir des
résultats produits par run_benchmark.sh, pour le dossier d'évaluation
de performance du mémoire (CPU, latence, paquets acceptés/rejetés).

Usage :
    python3 plot_benchmark.py
    (à lancer depuis le dossier contenant benchmark_results/baseline et
     benchmark_results/protected)

Sorties (dans benchmark_results/graphs/) :
    - cpu_comparison.png
    - latency_comparison.png
    - packets_comparison.png
"""

import os
import csv
import re
import matplotlib.pyplot as plt

RESULTS_DIR = "benchmark_results"
GRAPH_DIR = os.path.join(RESULTS_DIR, "graphs")
MODES = ["baseline", "protected"]
COLORS = {"baseline": "#d62728", "protected": "#2ca02c"}


def load_cpu(mode: str):
    path = os.path.join(RESULTS_DIR, mode, "cpu.csv")
    timestamps, values = [], []
    if not os.path.exists(path):
        return timestamps, values
    with open(path) as f:
        reader = csv.DictReader(f)
        t0 = None
        for row in reader:
            t = float(row["timestamp"])
            if t0 is None:
                t0 = t
            timestamps.append(t - t0)
            values.append(float(row["cpu_percent"]))
    return timestamps, values


def load_latency(mode: str):
    path = os.path.join(RESULTS_DIR, mode, "latency.csv")
    samples, values = [], []
    if not os.path.exists(path):
        return samples, values
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                samples.append(int(row["sample"]))
                values.append(float(row["latency_ms"]))
            except (ValueError, KeyError):
                continue
    return samples, values


def load_packet_counts(mode: str):
    path = os.path.join(RESULTS_DIR, mode, "traffic_summary.txt")
    sent, received = None, None
    if not os.path.exists(path):
        return sent, received
    with open(path) as f:
        content = f.read()
    m_sent = re.search(r"envoyés par l'attaquant.*?:\s*(\d+)", content)
    m_recv = re.search(r"reçus côté target-server.*?:\s*(\d+)", content)
    if m_sent:
        sent = int(m_sent.group(1))
    if m_recv:
        received = int(m_recv.group(1))
    return sent, received


def plot_cpu():
    plt.figure(figsize=(9, 5))
    for mode in MODES:
        t, v = load_cpu(mode)
        if t:
            plt.plot(t, v, label=mode, color=COLORS[mode])
    plt.xlabel("Temps écoulé (s)")
    plt.ylabel("Occupation CPU du routeur (%)")
    plt.title("Occupation CPU pendant l'attaque : baseline vs protected")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPH_DIR, "cpu_comparison.png"), dpi=150)
    plt.close()


def plot_latency():
    plt.figure(figsize=(9, 5))
    for mode in MODES:
        s, v = load_latency(mode)
        if s:
            plt.plot(s, v, label=mode, color=COLORS[mode], marker="o", markersize=2, linewidth=1)
    plt.xlabel("Échantillon (ping successif)")
    plt.ylabel("Latence (ms)")
    plt.title("Latence client légitime -> serveur : baseline vs protected")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPH_DIR, "latency_comparison.png"), dpi=150)
    plt.close()


def plot_packets():
    labels, sent_vals, recv_vals = [], [], []
    for mode in MODES:
        sent, received = load_packet_counts(mode)
        if sent is not None and received is not None:
            labels.append(mode)
            sent_vals.append(sent)
            recv_vals.append(received)

    if not labels:
        return

    x = range(len(labels))
    width = 0.35
    plt.figure(figsize=(8, 5))
    plt.bar([i - width / 2 for i in x], sent_vals, width, label="Paquets envoyés (attaquant)", color="#7f7f7f")
    plt.bar([i + width / 2 for i in x], recv_vals, width, label="Paquets reçus (cible)", color="#1f77b4")
    plt.xticks(list(x), labels)
    plt.ylabel("Nombre de paquets")
    plt.title("Paquets envoyés vs reçus : baseline vs protected")
    plt.legend()
    plt.grid(True, axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPH_DIR, "packets_comparison.png"), dpi=150)
    plt.close()


def plot_entropy():
    """Trace l'entropie des IP sources au fil du temps, si ai_engine.py a été
    lancé avec --log-csv (colonne source_entropy). Une hausse brusque signale
    une attaque distribuée (voir README, section détection multi-critères)."""
    plt.figure(figsize=(9, 5))
    plotted = False
    for mode in MODES:
        path = os.path.join(RESULTS_DIR, mode, "ai_engine_metrics.csv")
        if not os.path.exists(path):
            continue
        timestamps, entropies = [], []
        with open(path) as f:
            reader = csv.DictReader(f)
            t0 = None
            seen = set()
            for row in reader:
                t = float(row["timestamp"])
                if t0 is None:
                    t0 = t
                if t in seen:
                    continue
                seen.add(t)
                timestamps.append(t - t0)
                entropies.append(float(row["source_entropy"]))
        if timestamps:
            plt.plot(timestamps, entropies, label=mode, color=COLORS[mode])
            plotted = True

    if not plotted:
        return
    plt.xlabel("Temps écoulé (s)")
    plt.ylabel("Entropie des IP sources (bits)")
    plt.title("Entropie des IP sources : baseline vs protected")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(os.path.join(GRAPH_DIR, "entropy_comparison.png"), dpi=150)
    plt.close()


def main():
    os.makedirs(GRAPH_DIR, exist_ok=True)
    plot_cpu()
    plot_latency()
    plot_packets()
    plot_entropy()
    print(f"Graphiques générés dans {GRAPH_DIR}/")


if __name__ == "__main__":
    main()
