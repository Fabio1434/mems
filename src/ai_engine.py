#!/usr/bin/env python3
"""
ai_engine.py
Moteur de détection d'anomalies en espace utilisateur (Isolation Forest),
couplé au filtre XDP/eBPF via BCC (BPF Compiler Collection).

Rôle :
  1. Compiler et attacher xdp_filter.c à l'interface réseau donnée (via bcc).
  2. Lire périodiquement les statistiques multi-critères par IP source dans
     la BPF Map "ip_stats" (paquets, octets, paquets SYN, paquets UDP).
  3. Dériver 4 features par IP : débit (pps), ratio de SYN sans ACK
     (SYN flood), ratio de paquets UDP (UDP flood), taille moyenne de paquet.
  4. Entraîner un modèle Isolation Forest MULTI-DIMENSIONNEL sur ces
     features, sur une FENÊTRE GLISSANTE d'historique par IP, et le
     RÉENTRAÎNER PÉRIODIQUEMENT (toutes les RETRAIN_INTERVAL_SEC secondes)
     pour s'adapter à l'évolution du trafic normal dans le temps
     (concept drift) -- le modèle initial ne serait sinon jamais mis à
     jour après son premier entraînement.
  5. Calculer à chaque cycle l'entropie de Shannon de la répartition du
     trafic entre IP sources, pour détecter les attaques DISTRIBUÉES
     (botnet) où chaque IP individuelle reste sous le seuil de détection
     classique.
  6. Inscrire les IP jugées malveillantes dans la BPF Map "blacklist"
     (avec expiration TTL automatique), et journaliser une explication
     de chaque décision (feature la plus atypique).
  7. Exposer un DASHBOARD WEB TEMPS RÉEL (serveur HTTP intégré) affichant
     le trafic par IP, l'entropie, les alertes et la blacklist en direct
     -- pensé pour la démonstration en direct devant le jury.

Prérequis (à installer dans le conteneur xdp-router) :
  apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
  pip3 install scikit-learn numpy pandas
  -> NB : bcc nécessite les headers du noyau HÔTE (le kernel du conteneur
     est celui de la machine qui l'exécute). En environnement Containerlab,
     s'assurer que linux-headers-$(uname -r) est bien disponible/installable
     sur l'hôte, sinon monter /usr/src et /lib/modules en bind read-only.

Usage :
  sudo python3 ai_engine.py --iface eth1
  # Dashboard accessible sur http://<ip-du-routeur>:8080 (--dashboard-port)
"""

import argparse
import csv
import json
import math
import time
import socket
import struct
import logging
import threading
import http.server
from pathlib import Path
from collections import deque, defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest
from bcc import BPF

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
POLL_INTERVAL_SEC = 2          # fréquence de lecture des BPF Maps
TRAINING_WINDOW = 150          # nb d'échantillons minimum avant le 1er entraînement
                                # (empiriquement nécessaire pour bien séparer les
                                # anomalies subtiles -- voir tests/test_ai_engine_logic.py)
MAX_HISTORY_PER_IP = 600       # taille de la fenêtre glissante par IP (~20 min à 2s/cycle)
RETRAIN_INTERVAL_SEC = 300     # ré-entraînement périodique (concept drift) : 5 min
CONTAMINATION = 0.05           # proportion attendue d'anomalies (5%)
BLACKLIST_TTL_SEC = 60         # durée avant déblocage automatique d'une IP
ENTROPY_HISTORY_SIZE = 15
ENTROPY_SPIKE_THRESHOLD = 0.35
BPF_SOURCE_FILE = "xdp_filter.c"
XDP_FUNC_NAME = "xdp_filter_prog"
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"

# Ordre des features utilisées pour construire les vecteurs d'entrée du
# modèle Isolation Forest. Ajouter une feature = l'ajouter ici + dans
# extract_features() ; le reste du code (update/train/detect) s'adapte
# automatiquement.
FEATURE_NAMES = ["pps", "syn_ratio", "udp_ratio", "avg_pkt_size"]

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
        """Retourne {ip_str: {"packets","bytes","syn_count","udp_count"}}
        lu depuis la map ip_stats (struct ip_stat_t côté noyau)."""
        stats = {}
        for k, v in self.ip_stats_table.items():
            stats[ip_int_to_str(k.value)] = {
                "packets": v.packets,
                "bytes": v.bytes,
                "syn_count": v.syn_count,
                "udp_count": v.udp_count,
            }
        return stats

    def add_to_blacklist(self, ip_str: str):
        key = ip_str_to_key(ip_str, self.blacklist_table.Key)
        leaf = self.blacklist_table.Leaf(1)
        self.blacklist_table[key] = leaf

    def remove_from_blacklist(self, ip_str: str):
        key = ip_str_to_key(ip_str, self.blacklist_table.Key)
        try:
            del self.blacklist_table[key]
        except KeyError:
            pass

    def detach(self):
        self.bpf.remove_xdp(self.iface, 0)
        log.info("Programme XDP détaché de %s", self.iface)


# ------------------------------------------------------------------
# Extraction de features multi-critères par IP
# ------------------------------------------------------------------
def compute_pps(prev_stats: dict, curr_stats: dict, elapsed_sec: float) -> dict:
    """Débit (pps) par IP. Compatible ancien format (int) et nouveau (dict)."""
    pps = {}
    for ip_str, curr_val in curr_stats.items():
        curr_count = curr_val["packets"] if isinstance(curr_val, dict) else curr_val
        prev_val = prev_stats.get(ip_str, 0)
        prev_count = prev_val["packets"] if isinstance(prev_val, dict) else prev_val
        delta = max(curr_count - prev_count, 0)
        pps[ip_str] = delta / elapsed_sec if elapsed_sec > 0 else 0.0
    return pps


def extract_features(prev_stats: dict, curr_stats: dict, elapsed_sec: float) -> dict:
    """
    Calcule, pour chaque IP source, le vecteur de features défini par
    FEATURE_NAMES à partir de deux relevés successifs de ip_stats :

      - pps           : paquets/seconde (débit brut)
      - syn_ratio      : proportion de SYN-sans-ACK -> signature SYN flood
      - udp_ratio      : proportion de paquets UDP -> signature UDP flood
      - avg_pkt_size   : taille moyenne des paquets (octets)
    """
    features = {}
    for ip_str, curr in curr_stats.items():
        prev = prev_stats.get(
            ip_str, {"packets": 0, "bytes": 0, "syn_count": 0, "udp_count": 0}
        )

        d_packets = max(curr["packets"] - prev["packets"], 0)
        d_bytes = max(curr["bytes"] - prev["bytes"], 0)
        d_syn = max(curr["syn_count"] - prev["syn_count"], 0)
        d_udp = max(curr["udp_count"] - prev["udp_count"], 0)

        pps = d_packets / elapsed_sec if elapsed_sec > 0 else 0.0
        syn_ratio = (d_syn / d_packets) if d_packets > 0 else 0.0
        udp_ratio = (d_udp / d_packets) if d_packets > 0 else 0.0
        avg_pkt_size = (d_bytes / d_packets) if d_packets > 0 else 0.0

        features[ip_str] = {
            "pps": pps,
            "syn_ratio": syn_ratio,
            "udp_ratio": udp_ratio,
            "avg_pkt_size": avg_pkt_size,
        }
    return features


def compute_source_entropy(curr_stats: dict) -> float:
    """Entropie de Shannon (bits) de la répartition du trafic entre IP
    sources. Une hausse brusque signale une attaque distribuée (voir
    EntropyMonitor)."""
    total_packets = sum(
        (v["packets"] if isinstance(v, dict) else v) for v in curr_stats.values()
    )
    if total_packets == 0 or len(curr_stats) <= 1:
        return 0.0

    entropy = 0.0
    for v in curr_stats.values():
        count = v["packets"] if isinstance(v, dict) else v
        if count <= 0:
            continue
        p = count / total_packets
        entropy -= p * math.log2(p)
    return entropy


class EntropyMonitor:
    """Moyenne mobile de l'entropie des IP sources + détection de pics
    évocateurs d'une attaque distribuée."""

    def __init__(self, history_size: int = ENTROPY_HISTORY_SIZE,
                 spike_threshold: float = ENTROPY_SPIKE_THRESHOLD):
        self.history = []
        self.history_size = history_size
        self.spike_threshold = spike_threshold

    def update_and_check(self, current_entropy: float):
        baseline = sum(self.history) / len(self.history) if self.history else current_entropy
        is_spike = len(self.history) >= 3 and (current_entropy - baseline) > self.spike_threshold
        self.history.append(current_entropy)
        if len(self.history) > self.history_size:
            self.history.pop(0)
        return is_spike, baseline


class TrafficAnomalyDetector:
    """
    Isolation Forest multi-dimensionnel (features définies par
    FEATURE_NAMES), avec fenêtre glissante par IP (MAX_HISTORY_PER_IP) et
    ré-entraînement périodique pour s'adapter au concept drift.
    """

    def __init__(self, contamination: float = CONTAMINATION):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.feature_history = defaultdict(lambda: deque(maxlen=MAX_HISTORY_PER_IP))
        self.is_trained = False
        self.last_train_time = None

    @staticmethod
    def _vector(feat: dict):
        return [feat[name] for name in FEATURE_NAMES]

    def update(self, ip_features: dict):
        for ip_str, feat in ip_features.items():
            self.feature_history[ip_str].append(self._vector(feat))

    def ready_to_train(self) -> bool:
        total_samples = sum(len(v) for v in self.feature_history.values())
        return total_samples >= TRAINING_WINDOW

    def train(self):
        samples = [row for values in self.feature_history.values() for row in values]
        if len(samples) < 2:
            return
        X = np.array(samples)
        self.model.fit(X)
        self.is_trained = True
        self.last_train_time = time.time()
        log.info("Modèle Isolation Forest (ré)entraîné sur %d échantillons (fenêtre glissante, features: %s)",
                  len(samples), ", ".join(FEATURE_NAMES))

    def due_for_retrain(self, now: float, interval_sec: float = RETRAIN_INTERVAL_SEC) -> bool:
        """True si un ré-entraînement périodique est dû (concept drift)."""
        if not self.is_trained:
            return False
        return (now - self.last_train_time) >= interval_sec

    def _feature_means(self) -> np.ndarray:
        samples = [row for values in self.feature_history.values() for row in values]
        if not samples:
            return np.zeros(len(FEATURE_NAMES))
        return np.array(samples).mean(axis=0)

    def detect(self, ip_features: dict) -> dict:
        """Retourne {ip_str: vecteur_features} pour les IP anormales (-1)."""
        if not self.is_trained or not ip_features:
            return {}
        ips = list(ip_features.keys())
        X = np.array([self._vector(ip_features[ip]) for ip in ips])
        predictions = self.model.predict(X)
        return {ip: X[i] for i, ip in enumerate(ips) if predictions[i] == -1}

    def explain(self, ip_str: str, feature_vector) -> str:
        means = self._feature_means()
        diffs = [(FEATURE_NAMES[i], feature_vector[i], means[i]) for i in range(len(FEATURE_NAMES))]
        diffs.sort(key=lambda t: abs(t[1] - t[2]) / (abs(t[2]) + 1e-6), reverse=True)
        top = diffs[0]
        return f"feature la plus atypique: {top[0]}={top[1]:.2f} (moyenne trafic normal: {top[2]:.2f})"


# ------------------------------------------------------------------
# Dashboard web temps réel
# ------------------------------------------------------------------
class DashboardState:
    """État partagé thread-safe entre la boucle de détection et le
    serveur HTTP du dashboard."""

    def __init__(self):
        self.lock = threading.Lock()
        self.latest_features = {}
        self.entropy_history = []   # [[timestamp, entropy], ...]
        self.blacklist_expiry = {}  # ip_str -> timestamp d'expiration
        self.alerts = []            # [{"timestamp":, "level":, "message":}, ...]

    def record_cycle(self, features: dict, entropy: float, blacklisted_since: dict, ttl: int):
        with self.lock:
            self.latest_features = features
            self.entropy_history.append([time.time(), entropy])
            if len(self.entropy_history) > 300:
                self.entropy_history.pop(0)
            self.blacklist_expiry = {ip: ts + ttl for ip, ts in blacklisted_since.items()}

    def add_alert(self, level: str, message: str):
        with self.lock:
            self.alerts.append({"timestamp": time.time(), "level": level, "message": message})
            if len(self.alerts) > 50:
                self.alerts.pop(0)

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "timestamp": time.time(),
                "ips": self.latest_features,
                "entropy_history": list(self.entropy_history[-120:]),
                "blacklist": self.blacklist_expiry,
                "alerts": list(self.alerts[-20:]),
                "feature_names": FEATURE_NAMES,
            }


def make_dashboard_handler(state: DashboardState):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

        def do_GET(self):
            if self.path.startswith("/api/stats"):
                payload = json.dumps(state.snapshot()).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            else:
                super().do_GET()

        def log_message(self, fmt, *args):
            pass  # silence les logs HTTP par défaut (bruyants en continu)

    return Handler


def start_dashboard_server(state: DashboardState, port: int):
    handler = make_dashboard_handler(state)
    server = http.server.ThreadingHTTPServer(("0.0.0.0", port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    log.info("Dashboard temps réel disponible sur http://<ip-du-routeur>:%d", port)
    return server


def main():
    parser = argparse.ArgumentParser(description="Moteur IA de détection DDoS (XDP + Isolation Forest multi-critères)")
    parser.add_argument("--iface", required=True, help="Interface réseau où attacher le programme XDP (ex: eth1)")
    parser.add_argument("--log-csv", default=None, help="Fichier CSV de log détaillé par cycle (pour benchmark)")
    parser.add_argument("--ttl", type=int, default=BLACKLIST_TTL_SEC,
                         help=f"Durée avant déblocage automatique d'une IP (défaut: {BLACKLIST_TTL_SEC}s)")
    parser.add_argument("--retrain-interval", type=int, default=RETRAIN_INTERVAL_SEC,
                         help=f"Intervalle de ré-entraînement périodique en secondes (défaut: {RETRAIN_INTERVAL_SEC}s)")
    parser.add_argument("--dashboard-port", type=int, default=8080,
                         help="Port du dashboard web temps réel (défaut: 8080)")
    parser.add_argument("--no-dashboard", action="store_true", help="Désactive le dashboard web")
    args = parser.parse_args()

    log.info("Démarrage du moteur IA sur %s (TTL: %ds, ré-entraînement: %ds)",
              args.iface, args.ttl, args.retrain_interval)
    bpf_maps = BPFMapInterface(args.iface)
    detector = TrafficAnomalyDetector()
    entropy_monitor = EntropyMonitor()

    state = DashboardState()
    if not args.no_dashboard:
        start_dashboard_server(state, args.dashboard_port)

    csv_writer, csv_file = None, None
    if args.log_csv:
        csv_file = open(args.log_csv, "w", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["timestamp", "ip"] + FEATURE_NAMES + ["blacklisted", "source_entropy"])

    prev_stats = {}
    blacklisted_since = {}

    try:
        while True:
            start = time.time()

            curr_stats = bpf_maps.read_ip_stats()
            features = extract_features(prev_stats, curr_stats, POLL_INTERVAL_SEC)
            source_entropy = compute_source_entropy(curr_stats)
            prev_stats = curr_stats

            detector.update(features)

            # 1er entraînement
            if not detector.is_trained and detector.ready_to_train():
                detector.train()
                state.add_alert("info", "Modèle initial entraîné")

            # Ré-entraînement périodique (concept drift)
            if detector.due_for_retrain(start, args.retrain_interval):
                detector.train()
                state.add_alert("info", "Modèle ré-entraîné (fenêtre glissante mise à jour)")

            # Détection par IP (multi-critères)
            anomalies = detector.detect(features) if detector.is_trained else {}
            for ip_str, vec in anomalies.items():
                if ip_str not in blacklisted_since:
                    explanation = detector.explain(ip_str, vec)
                    log.warning("Anomalie détectée : %s -> blacklist (TTL %ds) | %s",
                                ip_str, args.ttl, explanation)
                    bpf_maps.add_to_blacklist(ip_str)
                    blacklisted_since[ip_str] = start
                    state.add_alert("danger", f"{ip_str} bloquée -- {explanation}")

            # Expiration TTL
            expired = [ip for ip, ts in blacklisted_since.items() if start - ts >= args.ttl]
            for ip_str in expired:
                log.info("TTL expiré pour %s -> déblocage automatique", ip_str)
                bpf_maps.remove_from_blacklist(ip_str)
                del blacklisted_since[ip_str]
                state.add_alert("info", f"{ip_str} débloquée (TTL expiré)")

            # Détection distribuée par entropie
            is_spike, baseline = entropy_monitor.update_and_check(source_entropy)
            if is_spike:
                msg = (f"Hausse anormale de l'entropie des IP sources : {source_entropy:.2f} bits "
                       f"(moyenne récente: {baseline:.2f}) -- attaque distribuée possible")
                log.warning(msg)
                state.add_alert("warning", msg)

            # Mise à jour de l'état du dashboard
            state.record_cycle(features, source_entropy, blacklisted_since, args.ttl)

            # Logging CSV optionnel
            if csv_writer:
                for ip_str, feat in features.items():
                    row = [start, ip_str] + [feat[name] for name in FEATURE_NAMES]
                    row += [ip_str in blacklisted_since, source_entropy]
                    csv_writer.writerow(row)
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
