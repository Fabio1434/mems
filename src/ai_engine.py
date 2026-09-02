#!/usr/bin/env python3
"""
ai_engine.py
Moteur de détection d'anomalies en espace utilisateur (Isolation Forest),
couplé au filtre XDP/eBPF via BCC (BPF Compiler Collection).

Rôle :
  1. Compiler et attacher xdp_filter.c à l'interface réseau donnée (via bcc).
  2. Lire périodiquement les statistiques multi-critères par IP source dans
     la BPF Map "ip_stats" (paquets, octets, paquets SYN).
  3. Dériver 3 features par IP : débit (pps), ratio de SYN sans ACK
     (signature de SYN flood), taille moyenne de paquet.
  4. Entraîner / faire inférer un modèle Isolation Forest MULTI-DIMENSIONNEL
     sur ces 3 features -- une IP peut être jugée anormale même si son débit
     seul semble normal (ex: 100% de SYN sans ACK à débit modéré).
  5. Calculer à chaque cycle l'ENTROPIE DE SHANNON de la répartition du
     trafic entre IP sources : une chute de trafic concentré sur peu d'IP
     signale une attaque volumétrique classique, tandis qu'une hausse
     d'entropie (trafic qui se répartit soudainement sur beaucoup plus
     d'IP qu'à l'habitude) est la signature d'une attaque DISTRIBUÉE
     (botnet) où chaque IP individuelle reste sous le seuil de détection
     classique. Ce signal est loggé/alerté (voir --log-csv).
  6. Inscrire les IP jugées malveillantes dans la BPF Map "blacklist", que
     xdp_filter.c consulte pour un DROP immédiat au niveau noyau. Chaque
     décision de blocage est journalisée avec les valeurs de features qui
     l'ont déclenchée (explicabilité).

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
import math
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
TRAINING_WINDOW = 150          # nombre d'échantillons avant d'entraîner le modèle
                                # (empiriquement, un Isolation Forest a besoin d'un
                                # historique substantiel pour bien séparer les
                                # anomalies subtiles -- voir tests/test_ai_engine_logic.py
                                # et le README pour la justification de cette valeur)
CONTAMINATION = 0.05           # proportion attendue d'anomalies (5%)
BLACKLIST_TTL_SEC = 60         # durée avant déblocage automatique d'une IP
                                # (évite qu'un faux positif reste bloqué indéfiniment)
ENTROPY_HISTORY_SIZE = 15      # nombre de cycles gardés pour la moyenne mobile d'entropie
ENTROPY_SPIKE_THRESHOLD = 0.35 # écart (en bits) au-dessus de la moyenne mobile pour alerter
BPF_SOURCE_FILE = "xdp_filter.c"
XDP_FUNC_NAME = "xdp_filter_prog"

# Noms des features, dans l'ordre utilisé pour construire les vecteurs
# d'entrée du modèle Isolation Forest. Garder cet ordre synchronisé avec
# extract_features().
FEATURE_NAMES = ["pps", "syn_ratio", "avg_pkt_size"]

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
        """Retourne {ip_str: {"packets", "bytes", "syn_count"}} lu depuis
        la map ip_stats (struct ip_stat_t côté noyau)."""
        stats = {}
        for k, v in self.ip_stats_table.items():
            stats[ip_int_to_str(k.value)] = {
                "packets": v.packets,
                "bytes": v.bytes,
                "syn_count": v.syn_count,
            }
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


# ------------------------------------------------------------------
# Extraction de features multi-critères par IP
# ------------------------------------------------------------------
def compute_pps(prev_stats: dict, curr_stats: dict, elapsed_sec: float) -> dict:
    """Débit (pps) par IP entre deux relevés cumulatifs de ip_stats.
    Compatible avec l'ancien format (curr_stats[ip] = int) ET le nouveau
    format multi-critères (curr_stats[ip] = {"packets": ..., ...})."""
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
    Calcule, pour chaque IP source, un vecteur de 3 features à partir de
    deux relevés successifs de ip_stats (multi-critères) :

      - pps           : paquets/seconde (débit brut)
      - syn_ratio      : proportion de paquets SYN-sans-ACK parmi les
                        nouveaux paquets de l'intervalle (0.0 à 1.0)
                        -> proche de 1.0 = signature typique de SYN flood
      - avg_pkt_size   : taille moyenne des paquets (octets) sur l'intervalle
                        -> un flood utilise souvent des paquets petits et
                           très uniformes, contrairement au trafic applicatif

    Retourne {ip_str: {"pps": ..., "syn_ratio": ..., "avg_pkt_size": ...}}
    """
    features = {}
    for ip_str, curr in curr_stats.items():
        prev = prev_stats.get(ip_str, {"packets": 0, "bytes": 0, "syn_count": 0})

        d_packets = max(curr["packets"] - prev["packets"], 0)
        d_bytes = max(curr["bytes"] - prev["bytes"], 0)
        d_syn = max(curr["syn_count"] - prev["syn_count"], 0)

        pps = d_packets / elapsed_sec if elapsed_sec > 0 else 0.0
        syn_ratio = (d_syn / d_packets) if d_packets > 0 else 0.0
        avg_pkt_size = (d_bytes / d_packets) if d_packets > 0 else 0.0

        features[ip_str] = {
            "pps": pps,
            "syn_ratio": syn_ratio,
            "avg_pkt_size": avg_pkt_size,
        }
    return features


def compute_source_entropy(curr_stats: dict) -> float:
    """
    Entropie de Shannon (en bits) de la répartition du trafic entre IP
    sources sur le cycle courant, basée sur le nombre total de paquets
    cumulés par IP (proxy simple mais efficace de la "part de trafic").

    - Entropie proche de 0   : trafic concentré sur très peu d'IP
                               (signature d'un flood mono-source classique,
                               déjà couvert par la détection par IP).
    - Entropie qui AUGMENTE brusquement au-delà de la moyenne récente :
      le trafic se répartit soudain sur beaucoup plus de sources qu'à
      l'habitude -> signature d'une attaque DISTRIBUÉE (botnet), où
      chaque IP individuelle peut rester sous le seuil de détection
      par IP tout en saturant collectivement la cible.
    """
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
    """Maintient une moyenne mobile de l'entropie des IP sources et signale
    les hausses brusques évocatrices d'une attaque distribuée."""

    def __init__(self, history_size: int = ENTROPY_HISTORY_SIZE,
                 spike_threshold: float = ENTROPY_SPIKE_THRESHOLD):
        self.history = []
        self.history_size = history_size
        self.spike_threshold = spike_threshold

    def update_and_check(self, current_entropy: float):
        """Retourne (is_spike, baseline_avg) puis met à jour l'historique."""
        if not self.history:
            baseline = current_entropy
        else:
            baseline = sum(self.history) / len(self.history)

        is_spike = (
            len(self.history) >= 3
            and (current_entropy - baseline) > self.spike_threshold
        )

        self.history.append(current_entropy)
        if len(self.history) > self.history_size:
            self.history.pop(0)

        return is_spike, baseline


class TrafficAnomalyDetector:
    """
    Encapsule le modèle Isolation Forest MULTI-DIMENSIONNEL (pps, syn_ratio,
    avg_pkt_size) et l'historique de features par IP.
    """

    def __init__(self, contamination: float = CONTAMINATION):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.feature_history = defaultdict(list)  # ip_str -> [[pps, syn_ratio, size], ...]
        self.is_trained = False

    def update(self, ip_features: dict):
        for ip_str, feat in ip_features.items():
            self.feature_history[ip_str].append(
                [feat["pps"], feat["syn_ratio"], feat["avg_pkt_size"]]
            )

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
        log.info("Modèle Isolation Forest entraîné sur %d échantillons (features: %s)",
                  len(samples), ", ".join(FEATURE_NAMES))

    def _feature_means(self) -> np.ndarray:
        """Moyenne de chaque feature sur l'historique d'entraînement, pour
        l'explicabilité des décisions de blocage."""
        samples = [row for values in self.feature_history.values() for row in values]
        if not samples:
            return np.zeros(len(FEATURE_NAMES))
        return np.array(samples).mean(axis=0)

    def detect(self, ip_features: dict) -> dict:
        """
        Retourne {ip_str: vecteur_features} pour les IP jugées anormales
        (-1 selon la convention scikit-learn). Le vecteur est renvoyé pour
        permettre un message d'explicabilité au moment du blocage.
        """
        if not self.is_trained or not ip_features:
            return {}
        ips = list(ip_features.keys())
        X = np.array([
            [ip_features[ip]["pps"], ip_features[ip]["syn_ratio"], ip_features[ip]["avg_pkt_size"]]
            for ip in ips
        ])
        predictions = self.model.predict(X)
        return {ip: X[i] for i, ip in enumerate(ips) if predictions[i] == -1}

    def explain(self, ip_str: str, feature_vector) -> str:
        """Construit un message d'explicabilité : quelle(s) feature(s) de
        cette IP s'écartent le plus de la moyenne du trafic d'entraînement."""
        means = self._feature_means()
        diffs = [(FEATURE_NAMES[i], feature_vector[i], means[i]) for i in range(len(FEATURE_NAMES))]
        # Trie par écart relatif décroissant (feature la plus "anormale" en premier)
        diffs.sort(key=lambda t: abs(t[1] - t[2]) / (abs(t[2]) + 1e-6), reverse=True)
        top = diffs[0]
        return f"feature la plus atypique: {top[0]}={top[1]:.2f} (moyenne trafic normal: {top[2]:.2f})"


def main():
    parser = argparse.ArgumentParser(description="Moteur IA de détection DDoS (XDP + Isolation Forest multi-critères)")
    parser.add_argument("--iface", required=True, help="Interface réseau où attacher le programme XDP (ex: eth1)")
    parser.add_argument(
        "--log-csv", default=None,
        help="Chemin d'un fichier CSV où logger chaque cycle (timestamp, ip, pps, syn_ratio, "
             "avg_pkt_size, blacklisted, source_entropy) -- utile pour un benchmark précis",
    )
    parser.add_argument(
        "--ttl", type=int, default=BLACKLIST_TTL_SEC,
        help=f"Durée en secondes avant déblocage automatique d'une IP blacklistée (défaut: {BLACKLIST_TTL_SEC})",
    )
    args = parser.parse_args()

    log.info("Démarrage du moteur IA de détection d'anomalies sur %s (TTL blacklist: %ds)", args.iface, args.ttl)
    bpf_maps = BPFMapInterface(args.iface)
    detector = TrafficAnomalyDetector()
    entropy_monitor = EntropyMonitor()

    csv_writer, csv_file = None, None
    if args.log_csv:
        csv_file = open(args.log_csv, "w", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["timestamp", "ip", "pps", "syn_ratio", "avg_pkt_size",
                              "blacklisted", "source_entropy"])

    prev_stats = {}
    blacklisted_since = {}  # ip_str -> timestamp de mise en blacklist

    try:
        while True:
            start = time.time()

            # 1. Lire les stats multi-critères et dériver les features par IP
            curr_stats = bpf_maps.read_ip_stats()
            features = extract_features(prev_stats, curr_stats, POLL_INTERVAL_SEC)
            source_entropy = compute_source_entropy(curr_stats)
            prev_stats = curr_stats

            detector.update(features)

            if not detector.is_trained and detector.ready_to_train():
                detector.train()

            # 2. Détection d'anomalie par IP (multi-critères) et blacklist
            anomalies = detector.detect(features) if detector.is_trained else {}
            for ip_str, vec in anomalies.items():
                if ip_str not in blacklisted_since:
                    log.warning(
                        "Anomalie détectée : %s -> blacklist (TTL %ds) | %s",
                        ip_str, args.ttl, detector.explain(ip_str, vec),
                    )
                    bpf_maps.add_to_blacklist(ip_str)
                    blacklisted_since[ip_str] = start

            # 3. Débloquer automatiquement les IP dont le TTL a expiré
            expired = [ip for ip, ts in blacklisted_since.items() if start - ts >= args.ttl]
            for ip_str in expired:
                log.info("TTL expiré pour %s -> déblocage automatique", ip_str)
                bpf_maps.remove_from_blacklist(ip_str)
                del blacklisted_since[ip_str]

            # 4. Détection d'attaque DISTRIBUÉE via l'entropie des IP sources
            is_spike, baseline = entropy_monitor.update_and_check(source_entropy)
            if is_spike:
                log.warning(
                    "Hausse anormale de l'entropie des IP sources : %.2f bits "
                    "(moyenne récente: %.2f bits) -- signature possible d'attaque "
                    "distribuée (nombreuses sources à faible débit individuel)",
                    source_entropy, baseline,
                )

            # 5. Logging CSV optionnel (précis, pour les benchmarks)
            if csv_writer:
                for ip_str, feat in features.items():
                    csv_writer.writerow([
                        start, ip_str, feat["pps"], feat["syn_ratio"], feat["avg_pkt_size"],
                        ip_str in blacklisted_since, source_entropy,
                    ])
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
