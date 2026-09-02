#!/usr/bin/env python3
"""
ai_engine.py
Moteur de détection d'anomalies en espace utilisateur (Isolation Forest),
couplé au filtre XDP/eBPF via BCC (BPF Compiler Collection).

Rôle :
  1. Compiler et attacher xdp_filter.c à l'interface réseau donnée (via bcc).
  2. Lire périodiquement les compteurs de paquets par IP source dans la
     BPF Map "ip_stats".
  3. Calculer le débit (paquets/seconde) de chaque IP entre deux lectures.
  4. Entraîner / faire inférer un modèle Isolation Forest sur ces débits
     pour repérer les IP au comportement anormal (ex: 20 pps -> 50000 pps).
  5. Inscrire les IP jugées malveillantes dans la BPF Map "blacklist", que
     xdp_filter.c consulte pour un DROP immédiat au niveau noyau.

Prérequis (à installer dans le conteneur xdp-router) :
  apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
  pip3 install scikit-learn numpy pandas
  -> NB : bcc nécessite les headers du noyau HÔTE (le kernel du conteneur
     est celui de la machine qui l'exécute). En environnement Containerlab,
     s'assurer que linux-headers-$(uname -r) est bien disponible/installable
     sur l'hôte, sinon monter /usr/src et /lib/modules en bind read-only.

Usage :
  sudo python3 ai_engine.py --iface eth1
"""

import argparse
import csv
import time
import socket
import struct
import logging
from collections import defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest
from bcc import BPF

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
POLL_INTERVAL_SEC = 2          # fréquence de lecture des BPF Maps
TRAINING_WINDOW = 30           # nombre d'échantillons avant d'entraîner le modèle
CONTAMINATION = 0.05           # proportion attendue d'anomalies (5%)
BLACKLIST_TTL_SEC = 60         # durée avant déblocage automatique d'une IP
                                # (évite qu'un faux positif reste bloqué indéfiniment)
BPF_SOURCE_FILE = "xdp_filter.c"
XDP_FUNC_NAME = "xdp_filter_prog"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ai_engine")


def ip_int_to_str(ip_int: int) -> str:
    """Convertit une IP uint32 (network byte order, telle que stockée par
    le programme XDP: ip->saddr) en chaîne lisible."""
    return socket.inet_ntoa(struct.pack("<I", ip_int))


def ip_str_to_key(ip_str: str, key_ctype):
    """Convertit une IP texte en clé ctypes attendue par la table bcc."""
    packed = struct.unpack("<I", socket.inet_aton(ip_str))[0]
    return key_ctype(packed)


class BPFMapInterface:
    """
    Charge xdp_filter.c via bcc, l'attache en XDP sur l'interface donnée,
    et expose une API simple pour lire ip_stats / écrire blacklist.
    """

    def __init__(self, iface: str, src_file: str = BPF_SOURCE_FILE):
        self.iface = iface
        log.info("Compilation et chargement de %s (bcc)...", src_file)
        self.bpf = BPF(src_file=src_file)
        fn = self.bpf.load_func(XDP_FUNC_NAME, BPF.XDP)
        self.bpf.attach_xdp(iface, fn, 0)
        log.info("Programme XDP attaché sur l'interface %s", iface)

        self.ip_stats_table = self.bpf["ip_stats"]
        self.blacklist_table = self.bpf["blacklist"]

    def read_ip_stats(self) -> dict:
        """Retourne {ip_str: total_packet_count} lu depuis la map ip_stats."""
        stats = {}
        for k, v in self.ip_stats_table.items():
            stats[ip_int_to_str(k.value)] = v.value
        return stats

    def add_to_blacklist(self, ip_str: str):
        """Ajoute une IP à la blacklist (XDP_DROP immédiat côté noyau)."""
        key = ip_str_to_key(ip_str, self.blacklist_table.Key)
        leaf = self.blacklist_table.Leaf(1)
        self.blacklist_table[key] = leaf

    def remove_from_blacklist(self, ip_str: str):
        """Retire une IP de la blacklist (utilisé lors de l'expiration TTL)."""
        key = ip_str_to_key(ip_str, self.blacklist_table.Key)
        try:
            del self.blacklist_table[key]
        except KeyError:
            pass

    def detach(self):
        self.bpf.remove_xdp(self.iface, 0)
        log.info("Programme XDP détaché de %s", self.iface)


class TrafficAnomalyDetector:
    """Encapsule le modèle Isolation Forest et l'historique de débits par IP."""

    def __init__(self, contamination: float = CONTAMINATION):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.pps_history = defaultdict(list)  # ip_str -> [pps_t0, pps_t1, ...]
        self.is_trained = False

    def update(self, ip_pps: dict):
        for ip_str, pps in ip_pps.items():
            self.pps_history[ip_str].append(pps)

    def ready_to_train(self) -> bool:
        total_samples = sum(len(v) for v in self.pps_history.values())
        return total_samples >= TRAINING_WINDOW

    def train(self):
        samples = [[pps] for values in self.pps_history.values() for pps in values]
        if len(samples) < 2:
            return
        X = np.array(samples)
        self.model.fit(X)
        self.is_trained = True
        log.info("Modèle Isolation Forest entraîné sur %d échantillons", len(samples))

    def detect(self, ip_pps: dict) -> list:
        """-1 = anomalie, 1 = normal (convention scikit-learn)."""
        if not self.is_trained or not ip_pps:
            return []
        ips = list(ip_pps.keys())
        X = np.array([[ip_pps[ip]] for ip in ips])
        predictions = self.model.predict(X)
        return [ip for ip, pred in zip(ips, predictions) if pred == -1]


def compute_pps(prev_stats: dict, curr_stats: dict, elapsed_sec: float) -> dict:
    """Débit (pps) par IP entre deux relevés cumulatifs de ip_stats."""
    pps = {}
    for ip_str, curr_count in curr_stats.items():
        prev_count = prev_stats.get(ip_str, 0)
        delta = max(curr_count - prev_count, 0)
        pps[ip_str] = delta / elapsed_sec if elapsed_sec > 0 else 0.0
    return pps


def main():
    parser = argparse.ArgumentParser(description="Moteur IA de détection DDoS (XDP + Isolation Forest)")
    parser.add_argument("--iface", required=True, help="Interface réseau où attacher le programme XDP (ex: eth1)")
    parser.add_argument(
        "--log-csv", default=None,
        help="Chemin d'un fichier CSV où logger chaque cycle (timestamp, ip, pps, blacklisted) "
             "-- utile pour un benchmark précis (voir scripts/run_benchmark.sh)",
    )
    parser.add_argument(
        "--ttl", type=int, default=BLACKLIST_TTL_SEC,
        help=f"Durée en secondes avant déblocage automatique d'une IP blacklistée (défaut: {BLACKLIST_TTL_SEC})",
    )
    args = parser.parse_args()

    log.info("Démarrage du moteur IA de détection d'anomalies sur %s (TTL blacklist: %ds)", args.iface, args.ttl)
    bpf_maps = BPFMapInterface(args.iface)
    detector = TrafficAnomalyDetector()

    csv_writer, csv_file = None, None
    if args.log_csv:
        csv_file = open(args.log_csv, "w", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["timestamp", "ip", "pps", "blacklisted"])

    prev_stats = {}
    blacklisted_since = {}  # ip_str -> timestamp de mise en blacklist

    try:
        while True:
            start = time.time()

            # 1. Lire les stats et calculer le débit par IP
            curr_stats = bpf_maps.read_ip_stats()
            pps = compute_pps(prev_stats, curr_stats, POLL_INTERVAL_SEC)
            prev_stats = curr_stats

            detector.update(pps)

            if not detector.is_trained and detector.ready_to_train():
                detector.train()

            # 2. Détecter les anomalies et blacklister les nouvelles IP
            anomalous_ips = set(detector.detect(pps)) if detector.is_trained else set()
            for ip_str in anomalous_ips:
                if ip_str not in blacklisted_since:
                    log.warning(
                        "Anomalie détectée : %s (%.1f pps) -> blacklist (TTL %ds)",
                        ip_str, pps.get(ip_str, 0.0), args.ttl,
                    )
                    bpf_maps.add_to_blacklist(ip_str)
                    blacklisted_since[ip_str] = start

            # 3. Débloquer automatiquement les IP dont le TTL a expiré
            expired = [
                ip for ip, ts in blacklisted_since.items()
                if start - ts >= args.ttl
            ]
            for ip_str in expired:
                log.info("TTL expiré pour %s -> déblocage automatique", ip_str)
                bpf_maps.remove_from_blacklist(ip_str)
                del blacklisted_since[ip_str]

            # 4. Logging CSV optionnel (précis, pour les benchmarks)
            if csv_writer:
                for ip_str, val in pps.items():
                    csv_writer.writerow([start, ip_str, val, ip_str in blacklisted_since])
                csv_file.flush()

            elapsed = time.time() - start
            time.sleep(max(0, POLL_INTERVAL_SEC - elapsed))

    except KeyboardInterrupt:
        log.info("Arrêt demandé (Ctrl+C)")
    finally:
        bpf_maps.detach()
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    main()
