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
  4. Entraîner un modèle Isolation Forest MULTI-DIMENSIONNEL sur une fenêtre
     glissante par IP, ré-entraîné PÉRIODIQUEMENT (concept drift).
  5. Calculer à chaque cycle l'entropie de Shannon de la répartition du
     trafic entre IP sources, pour détecter les attaques DISTRIBUÉES.
  6. Décider du sort de chaque IP anormale selon la configuration :
       - IP en LISTE BLANCHE       -> jamais bloquée, quoi qu'il arrive
       - MODE DRY-RUN actif        -> détectée et journalisée, PAS bloquée
       - sinon                     -> blacklistée (BPF Map), avec TTL
  7. Exposer un DASHBOARD WEB TEMPS RÉEL (serveur HTTP intégré).

Configuration :
  Tous les paramètres (seuils, TTL, whitelist, dry-run, dashboard) sont
  définis dans un fichier YAML (voir config/example.yaml) plutôt que codés
  en dur -- un fichier de config différent par réseau/environnement testé.
  Les arguments en ligne de commande, s'ils sont fournis, ont priorité sur
  le fichier de configuration.

Prérequis (à installer dans le conteneur xdp-router) :
  apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r)
  pip3 install scikit-learn numpy pandas pyyaml
  -> NB : bcc nécessite les headers du noyau HÔTE (le kernel du conteneur
     est celui de la machine qui l'exécute).

Usage :
  # Avec un fichier de config (recommandé pour un nouveau déploiement) :
  sudo python3 ai_engine.py --config config/config.yaml

  # Ou entièrement en ligne de commande (utilise les valeurs par défaut) :
  sudo python3 ai_engine.py --iface eth1
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
import urllib.parse
from pathlib import Path
from collections import deque, defaultdict

import numpy as np
from sklearn.ensemble import IsolationForest
from bcc import BPF

try:
    import joblib
except ImportError:
    joblib = None

try:
    import yaml
except ImportError:
    yaml = None

# ------------------------------------------------------------------
# Valeurs par défaut (utilisées si absentes du fichier de config et non
# fournies en ligne de commande)
# ------------------------------------------------------------------
DEFAULT_CONFIG = {
    "interface": None,
    "detection": {
        "contamination": 0.05,
        "training_window": 150,
        "max_history_per_ip": 600,
        "retrain_interval_sec": 300,
        "poll_interval_sec": 2,
        # Chemin de sauvegarde/chargement du modèle entraîné (joblib). Si
        # renseigné, le modèle est rechargé au démarrage s'il existe déjà
        # (évite de repartir de zéro -- et donc sans détection -- à chaque
        # redémarrage), et resauvegardé après chaque entraînement.
        "model_path": None,
    },
    "blacklist": {
        "ttl_sec": 60,
        "dry_run": False,
        "whitelist": [],
    },
    "entropy": {
        "history_size": 15,
        "spike_threshold": 0.35,
    },
    "dashboard": {
        "enabled": True,
        "port": 8080,
        # Adresse d'écoute du serveur du dashboard. "127.0.0.1" par défaut
        # (accessible uniquement depuis la machine elle-même) -- mettre
        # "0.0.0.0" explicitement pour une démonstration nécessitant un
        # accès depuis un autre poste sur le réseau.
        "bind_host": "127.0.0.1",
        # Jeton optionnel requis (paramètre ?token=... dans l'URL) pour
        # accéder au dashboard et à l'API. Laisser vide/null pour désactiver
        # (à éviter en dehors d'un lab isolé -- le dashboard expose du
        # trafic réseau en clair sans ce jeton).
        "token": None,
    },
}

BPF_SOURCE_FILE = "xdp_filter.c"
XDP_FUNC_NAME = "xdp_filter_prog"
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"

# Ordre des features utilisées pour construire les vecteurs d'entrée du
# modèle Isolation Forest.
FEATURE_NAMES = ["pps", "syn_ratio", "udp_ratio", "avg_pkt_size"]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("ai_engine")


def _deep_merge(base: dict, override: dict) -> dict:
    """Fusionne `override` dans `base` récursivement (sans muter `base`)."""
    result = dict(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def load_config(path) -> dict:
    """Charge un fichier YAML de configuration et le fusionne avec les
    valeurs par défaut (DEFAULT_CONFIG). Un fichier partiel (qui ne
    surcharge que certaines clés) est parfaitement valide."""
    if path is None:
        return dict(DEFAULT_CONFIG)
    if yaml is None:
        raise RuntimeError("pyyaml n'est pas installé (pip3 install pyyaml) -- requis pour --config")
    with open(path) as f:
        user_config = yaml.safe_load(f) or {}
    return _deep_merge(DEFAULT_CONFIG, user_config)


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
    pps = {}
    for ip_str, curr_val in curr_stats.items():
        curr_count = curr_val["packets"] if isinstance(curr_val, dict) else curr_val
        prev_val = prev_stats.get(ip_str, 0)
        prev_count = prev_val["packets"] if isinstance(prev_val, dict) else prev_val
        delta = max(curr_count - prev_count, 0)
        pps[ip_str] = delta / elapsed_sec if elapsed_sec > 0 else 0.0
    return pps


def extract_features(prev_stats: dict, curr_stats: dict, elapsed_sec: float) -> dict:
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
            "pps": pps, "syn_ratio": syn_ratio,
            "udp_ratio": udp_ratio, "avg_pkt_size": avg_pkt_size,
        }
    return features


def compute_source_entropy(curr_stats: dict) -> float:
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
    def __init__(self, history_size: int = 15, spike_threshold: float = 0.35):
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
    """Isolation Forest multi-dimensionnel, fenêtre glissante par IP,
    ré-entraînement périodique. Tous les hyperparamètres sont injectés
    (pas de constantes globales) pour permettre une config par déploiement."""

    def __init__(self, contamination: float = 0.05, training_window: int = 150,
                 max_history_per_ip: int = 600):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.training_window = training_window
        self.max_history_per_ip = max_history_per_ip
        self.feature_history = defaultdict(lambda: deque(maxlen=max_history_per_ip))
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
        return total_samples >= self.training_window

    def train(self):
        samples = [row for values in self.feature_history.values() for row in values]
        if len(samples) < 2:
            return
        X = np.array(samples)
        self.model.fit(X)
        self.is_trained = True
        self.last_train_time = time.time()
        log.info("Modèle Isolation Forest (ré)entraîné sur %d échantillons (features: %s)",
                  len(samples), ", ".join(FEATURE_NAMES))

    def due_for_retrain(self, now: float, interval_sec: float) -> bool:
        if not self.is_trained:
            return False
        return (now - self.last_train_time) >= interval_sec

    def save(self, path: str):
        """Sauvegarde le modèle entraîné sur disque (joblib). Ne sauvegarde
        PAS l'historique de features (recalculé naturellement au fil du
        trafic après redémarrage) -- seulement le modèle scikit-learn."""
        if joblib is None:
            log.warning("joblib n'est pas installé -- impossible de sauvegarder le modèle (pip3 install joblib)")
            return
        if not self.is_trained:
            return
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.model, path)
        log.info("Modèle sauvegardé sur %s", path)

    def load(self, path: str) -> bool:
        """Charge un modèle précédemment sauvegardé. Retourne True si le
        chargement a réussi. Permet d'éviter une fenêtre de vulnérabilité
        (aucune détection possible) le temps de réaccumuler un historique
        après un redémarrage."""
        if joblib is None:
            log.warning("joblib n'est pas installé -- impossible de charger le modèle (pip3 install joblib)")
            return False
        if not Path(path).exists():
            return False
        try:
            self.model = joblib.load(path)
            self.is_trained = True
            self.last_train_time = time.time()
            log.info("Modèle chargé depuis %s (ré-entraînement périodique toujours actif)", path)
            return True
        except Exception as e:
            log.warning("Échec du chargement du modèle depuis %s : %s", path, e)
            return False

    def _feature_means(self) -> np.ndarray:
        samples = [row for values in self.feature_history.values() for row in values]
        if not samples:
            return np.zeros(len(FEATURE_NAMES))
        return np.array(samples).mean(axis=0)

    def detect(self, ip_features: dict) -> dict:
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
    def __init__(self):
        self.lock = threading.Lock()
        self.latest_features = {}
        self.entropy_history = []
        self.blacklist_expiry = {}       # ip -> timestamp d'expiration (blocage RÉEL)
        self.simulated_blacklist = {}    # ip -> timestamp de dernière détection (dry-run)
        self.whitelist = []
        self.dry_run = False
        self.alerts = []

    def set_mode(self, dry_run: bool, whitelist: list):
        with self.lock:
            self.dry_run = dry_run
            self.whitelist = list(whitelist)

    def record_cycle(self, features: dict, entropy: float, blacklisted_since: dict,
                      simulated_since: dict, ttl: int):
        with self.lock:
            self.latest_features = features
            self.entropy_history.append([time.time(), entropy])
            if len(self.entropy_history) > 300:
                self.entropy_history.pop(0)
            self.blacklist_expiry = {ip: ts + ttl for ip, ts in blacklisted_since.items()}
            self.simulated_blacklist = dict(simulated_since)

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
                "simulated_blacklist": self.simulated_blacklist,
                "whitelist": self.whitelist,
                "dry_run": self.dry_run,
                "alerts": list(self.alerts[-20:]),
                "feature_names": FEATURE_NAMES,
            }


def make_dashboard_handler(state: DashboardState, token: str = None):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

        def _token_ok(self) -> bool:
            if not token:
                return True
            query = urllib.parse.urlparse(self.path).query
            provided = urllib.parse.parse_qs(query).get("token", [None])[0]
            return provided == token

        def do_GET(self):
            if not self._token_ok():
                body = b"401 Unauthorized -- token manquant ou invalide (?token=...)"
                self.send_response(401)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

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
            pass

    return Handler


def start_dashboard_server(state: DashboardState, port: int, bind_host: str = "127.0.0.1", token: str = None):
    handler = make_dashboard_handler(state, token=token)
    server = http.server.ThreadingHTTPServer((bind_host, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    suffix = f"?token={token}" if token else ""
    log.info("Dashboard temps réel disponible sur http://%s:%d%s", bind_host, port, suffix)
    if bind_host == "0.0.0.0":
        log.warning("Dashboard exposé sur toutes les interfaces (0.0.0.0) -- "
                     "assurez-vous qu'un token est configuré si ce réseau n'est pas isolé.")
    return server


def build_settings(args) -> dict:
    """Fusionne le fichier de config (si fourni) et les arguments CLI
    (qui ont priorité). Retourne un dict de settings prêt à l'emploi."""
    config = load_config(args.config)

    iface = args.iface or config["interface"]
    if not iface:
        raise SystemExit("Aucune interface spécifiée (--iface ou 'interface:' dans le fichier de config)")

    ttl = args.ttl if args.ttl is not None else config["blacklist"]["ttl_sec"]
    retrain_interval = (args.retrain_interval if args.retrain_interval is not None
                         else config["detection"]["retrain_interval_sec"])
    dashboard_port = (args.dashboard_port if args.dashboard_port is not None
                       else config["dashboard"]["port"])
    dashboard_enabled = config["dashboard"]["enabled"] and not args.no_dashboard
    dry_run = bool(config["blacklist"]["dry_run"] or args.dry_run)
    whitelist = set(config["blacklist"].get("whitelist") or [])

    return {
        "iface": iface,
        "ttl": ttl,
        "retrain_interval": retrain_interval,
        "dashboard_port": dashboard_port,
        "dashboard_enabled": dashboard_enabled,
        "dashboard_bind_host": config["dashboard"]["bind_host"],
        "dashboard_token": config["dashboard"]["token"],
        "dry_run": dry_run,
        "whitelist": whitelist,
        "contamination": config["detection"]["contamination"],
        "training_window": config["detection"]["training_window"],
        "max_history_per_ip": config["detection"]["max_history_per_ip"],
        "poll_interval": config["detection"]["poll_interval_sec"],
        "model_path": config["detection"].get("model_path"),
        "entropy_history_size": config["entropy"]["history_size"],
        "entropy_spike_threshold": config["entropy"]["spike_threshold"],
    }


def main():
    parser = argparse.ArgumentParser(description="Moteur IA de détection DDoS (XDP + Isolation Forest multi-critères)")
    parser.add_argument("--config", default=None,
                         help="Fichier YAML de configuration (voir config/example.yaml). "
                              "Les options CLI ci-dessous, si fournies, ont priorité.")
    parser.add_argument("--iface", default=None, help="Interface réseau où attacher le programme XDP")
    parser.add_argument("--log-csv", default=None, help="Fichier CSV de log détaillé par cycle")
    parser.add_argument("--ttl", type=int, default=None, help="Durée avant déblocage automatique d'une IP")
    parser.add_argument("--retrain-interval", type=int, default=None, help="Intervalle de ré-entraînement (s)")
    parser.add_argument("--dashboard-port", type=int, default=None, help="Port du dashboard web")
    parser.add_argument("--no-dashboard", action="store_true", help="Désactive le dashboard web")
    parser.add_argument("--dry-run", action="store_true",
                         help="Force le mode simulation : détecte et journalise, ne bloque JAMAIS "
                              "(s'ajoute au réglage du fichier de config, ne le désactive pas)")
    parser.add_argument("--model-path", default=None,
                         help="Chemin de sauvegarde/chargement du modèle entraîné (joblib)")
    args = parser.parse_args()

    settings = build_settings(args)
    if args.model_path is not None:
        settings["model_path"] = args.model_path

    log.info("Démarrage -- iface=%s, TTL=%ds, ré-entraînement=%ds, DRY-RUN=%s, whitelist=%d IP(s)",
              settings["iface"], settings["ttl"], settings["retrain_interval"],
              settings["dry_run"], len(settings["whitelist"]))
    if settings["dry_run"]:
        log.warning("*** MODE SIMULATION ACTIF : aucune IP ne sera réellement bloquée ***")

    bpf_maps = BPFMapInterface(settings["iface"])
    detector = TrafficAnomalyDetector(
        contamination=settings["contamination"],
        training_window=settings["training_window"],
        max_history_per_ip=settings["max_history_per_ip"],
    )
    if settings["model_path"]:
        if detector.load(settings["model_path"]):
            log.info("Détection immédiatement active grâce au modèle rechargé (pas d'attente de %d échantillons)",
                      settings["training_window"])
    entropy_monitor = EntropyMonitor(
        history_size=settings["entropy_history_size"],
        spike_threshold=settings["entropy_spike_threshold"],
    )

    state = DashboardState()
    state.set_mode(settings["dry_run"], settings["whitelist"])
    if settings["dashboard_enabled"]:
        start_dashboard_server(
            state, settings["dashboard_port"],
            bind_host=settings["dashboard_bind_host"],
            token=settings["dashboard_token"],
        )

    csv_writer, csv_file = None, None
    if args.log_csv:
        csv_file = open(args.log_csv, "w", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["timestamp", "ip"] + FEATURE_NAMES + ["blacklisted", "dry_run_flagged", "source_entropy"])

    prev_stats = {}
    blacklisted_since = {}   # blocage RÉEL (BPF Map)
    simulated_since = {}     # détection en mode dry-run (jamais dans la BPF Map)

    try:
        while True:
            start = time.time()

            curr_stats = bpf_maps.read_ip_stats()
            features = extract_features(prev_stats, curr_stats, settings["poll_interval"])
            source_entropy = compute_source_entropy(curr_stats)
            prev_stats = curr_stats

            detector.update(features)

            if not detector.is_trained and detector.ready_to_train():
                detector.train()
                if settings["model_path"]:
                    detector.save(settings["model_path"])
                state.add_alert("info", "Modèle initial entraîné")

            if detector.due_for_retrain(start, settings["retrain_interval"]):
                detector.train()
                if settings["model_path"]:
                    detector.save(settings["model_path"])
                state.add_alert("info", "Modèle ré-entraîné (fenêtre glissante mise à jour)")

            anomalies = detector.detect(features) if detector.is_trained else {}
            for ip_str, vec in anomalies.items():
                if ip_str in settings["whitelist"]:
                    continue  # jamais bloquée, quoi qu'il arrive

                explanation = detector.explain(ip_str, vec)

                if settings["dry_run"]:
                    if ip_str not in simulated_since:
                        log.warning("[DRY-RUN] %s aurait été bloquée | %s", ip_str, explanation)
                        state.add_alert("warning", f"[SIMULATION] {ip_str} aurait été bloquée -- {explanation}")
                    simulated_since[ip_str] = start
                elif ip_str not in blacklisted_since:
                    log.warning("Anomalie détectée : %s -> blacklist (TTL %ds) | %s",
                                ip_str, settings["ttl"], explanation)
                    bpf_maps.add_to_blacklist(ip_str)
                    blacklisted_since[ip_str] = start
                    state.add_alert("danger", f"{ip_str} bloquée -- {explanation}")

            # Expiration TTL (blocage réel uniquement)
            expired = [ip for ip, ts in blacklisted_since.items() if start - ts >= settings["ttl"]]
            for ip_str in expired:
                log.info("TTL expiré pour %s -> déblocage automatique", ip_str)
                bpf_maps.remove_from_blacklist(ip_str)
                del blacklisted_since[ip_str]
                state.add_alert("info", f"{ip_str} débloquée (TTL expiré)")

            # Purge des entrées simulées trop anciennes (visibilité dashboard uniquement)
            sim_expired = [ip for ip, ts in simulated_since.items() if start - ts >= settings["ttl"]]
            for ip_str in sim_expired:
                del simulated_since[ip_str]

            is_spike, baseline = entropy_monitor.update_and_check(source_entropy)
            if is_spike:
                msg = (f"Hausse anormale de l'entropie des IP sources : {source_entropy:.2f} bits "
                       f"(moyenne récente: {baseline:.2f}) -- attaque distribuée possible")
                log.warning(msg)
                state.add_alert("warning", msg)

            state.record_cycle(features, source_entropy, blacklisted_since, simulated_since, settings["ttl"])

            if csv_writer:
                for ip_str, feat in features.items():
                    row = [start, ip_str] + [feat[name] for name in FEATURE_NAMES]
                    row += [ip_str in blacklisted_since, ip_str in simulated_since, source_entropy]
                    csv_writer.writerow(row)
                csv_file.flush()

            elapsed = time.time() - start
            time.sleep(max(0, settings["poll_interval"] - elapsed))

    except KeyboardInterrupt:
        log.info("Arrêt demandé (Ctrl+C)")
    finally:
        bpf_maps.detach()
        if csv_file:
            csv_file.close()


if __name__ == "__main__":
    main()
