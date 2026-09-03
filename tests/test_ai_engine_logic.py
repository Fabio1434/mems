#!/usr/bin/env python3
"""
test_ai_engine_logic.py
Tests unitaires pour la logique "pure" de ai_engine.py : conversion IP,
extraction de features multi-critères, entropie des IP sources, et
détection d'anomalies multi-dimensionnelle (Isolation Forest).

Ces tests NE nécessitent PAS bcc/eBPF (donc pas de noyau Linux privilégié) :
le module `bcc` est mocké, ce qui permet de valider la logique métier sur
n'importe quelle machine (CI, poste de développement) avant de tester le
lab complet avec Containerlab.

Usage :
    pip3 install pytest scikit-learn numpy
    pytest tests/test_ai_engine_logic.py -v
"""

import sys
import socket
import struct
import random
import math
import time
import types
import importlib.util
from pathlib import Path

import pytest

# ------------------------------------------------------------------
# Charger ai_engine.py en mockant `bcc` (non disponible hors environnement
# noyau Linux privilégié)
# ------------------------------------------------------------------
if "bcc" not in sys.modules:
    fake_bcc = types.ModuleType("bcc")

    class _FakeBPF:
        XDP = "xdp"

    fake_bcc.BPF = _FakeBPF
    sys.modules["bcc"] = fake_bcc

SRC_PATH = Path(__file__).resolve().parent.parent / "src" / "ai_engine.py"
spec = importlib.util.spec_from_file_location("ai_engine", SRC_PATH)
ai_engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ai_engine)

# Valeurs par défaut utilisées dans les tests (le module n'expose plus de
# constantes globales -- tous les hyperparamètres sont injectables, voir
# TrafficAnomalyDetector.__init__ et DEFAULT_CONFIG)
TEST_TRAINING_WINDOW = ai_engine.DEFAULT_CONFIG["detection"]["training_window"]
TEST_MAX_HISTORY_PER_IP = ai_engine.DEFAULT_CONFIG["detection"]["max_history_per_ip"]


# ------------------------------------------------------------------
# Tests : conversion d'adresses IP
# ------------------------------------------------------------------
def test_ip_int_to_str_roundtrip():
    original = "10.0.1.2"
    packed_int = struct.unpack("<I", socket.inet_aton(original))[0]
    assert ai_engine.ip_int_to_str(packed_int) == original


def test_ip_int_to_str_various_addresses():
    for ip in ["192.168.1.1", "127.0.0.1", "255.255.255.255", "0.0.0.0"]:
        packed_int = struct.unpack("<I", socket.inet_aton(ip))[0]
        assert ai_engine.ip_int_to_str(packed_int) == ip


# ------------------------------------------------------------------
# Tests : compute_pps (rétro-compatibilité ancien format entier)
# ------------------------------------------------------------------
def test_compute_pps_legacy_int_format():
    pps = ai_engine.compute_pps({"10.0.1.2": 100}, {"10.0.1.2": 300}, elapsed_sec=2.0)
    assert pps["10.0.1.2"] == 100.0


def test_compute_pps_counter_reset_guard():
    pps = ai_engine.compute_pps({"10.0.1.2": 500}, {"10.0.1.2": 10}, elapsed_sec=2.0)
    assert pps["10.0.1.2"] == 0.0


# ------------------------------------------------------------------
# Tests : extraction de features multi-critères
# ------------------------------------------------------------------
def test_extract_features_basic():
    prev = {"1.1.1.1": {"packets": 100, "bytes": 10000, "syn_count": 5, "udp_count": 0}}
    curr = {
        "1.1.1.1": {"packets": 300, "bytes": 30000, "syn_count": 10, "udp_count": 0},
        "9.9.9.9": {"packets": 5000, "bytes": 300000, "syn_count": 4990, "udp_count": 0},
    }
    feats = ai_engine.extract_features(prev, curr, elapsed_sec=2.0)

    assert feats["1.1.1.1"]["pps"] == pytest.approx(100.0)
    assert feats["1.1.1.1"]["avg_pkt_size"] == pytest.approx(100.0)  # (30000-10000)/(300-100)

    # 9.9.9.9 est une nouvelle IP (absente de `prev`) : signature de SYN flood
    assert feats["9.9.9.9"]["pps"] == pytest.approx(2500.0)
    assert feats["9.9.9.9"]["syn_ratio"] == pytest.approx(4990 / 5000)


def test_extract_features_udp_flood_signature():
    prev = {"1.1.1.1": {"packets": 100, "bytes": 10000, "syn_count": 0, "udp_count": 0}}
    curr = {
        "1.1.1.1": {"packets": 300, "bytes": 30000, "syn_count": 0, "udp_count": 0},
        "9.9.9.9": {"packets": 5000, "bytes": 200000, "syn_count": 0, "udp_count": 4980},
    }
    feats = ai_engine.extract_features(prev, curr, elapsed_sec=2.0)
    assert feats["9.9.9.9"]["udp_ratio"] == pytest.approx(4980 / 5000)
    assert feats["1.1.1.1"]["udp_ratio"] == 0.0


def test_extract_features_no_packets_no_division_by_zero():
    prev = {"1.1.1.1": {"packets": 100, "bytes": 1000, "syn_count": 0, "udp_count": 0}}
    curr = {"1.1.1.1": {"packets": 100, "bytes": 1000, "syn_count": 0, "udp_count": 0}}
    feats = ai_engine.extract_features(prev, curr, elapsed_sec=2.0)
    assert feats["1.1.1.1"]["pps"] == 0.0
    assert feats["1.1.1.1"]["syn_ratio"] == 0.0
    assert feats["1.1.1.1"]["udp_ratio"] == 0.0
    assert feats["1.1.1.1"]["avg_pkt_size"] == 0.0


# ------------------------------------------------------------------
# Tests : entropie de Shannon des IP sources
# ------------------------------------------------------------------
def test_entropy_concentrated_traffic_is_near_zero():
    """Trafic quasi-entièrement issu d'une seule IP -> entropie proche de 0."""
    stats = {
        "1.1.1.1": {"packets": 10000, "bytes": 0, "syn_count": 0},
        "2.2.2.2": {"packets": 1, "bytes": 0, "syn_count": 0},
    }
    assert ai_engine.compute_source_entropy(stats) < 0.1


def test_entropy_distributed_traffic_approaches_max():
    """Trafic uniformément réparti sur N IP -> entropie proche de log2(N)
    (signature typique d'une attaque distribuée/botnet)."""
    n = 50
    stats = {f"10.0.0.{i}": {"packets": 100, "bytes": 0, "syn_count": 0} for i in range(n)}
    entropy = ai_engine.compute_source_entropy(stats)
    assert entropy == pytest.approx(math.log2(n), abs=0.01)


def test_entropy_empty_or_single_ip_is_zero():
    assert ai_engine.compute_source_entropy({}) == 0.0
    assert ai_engine.compute_source_entropy(
        {"1.1.1.1": {"packets": 100, "bytes": 0, "syn_count": 0}}
    ) == 0.0


def test_entropy_monitor_flags_sudden_spike():
    """Une hausse brusque de l'entropie par rapport à la moyenne récente
    doit déclencher une alerte (signature d'attaque distribuée)."""
    monitor = ai_engine.EntropyMonitor(history_size=10, spike_threshold=0.35)
    for _ in range(5):
        is_spike, _ = monitor.update_and_check(2.0)
        assert not is_spike
    is_spike, baseline = monitor.update_and_check(6.0)
    assert is_spike
    assert baseline == pytest.approx(2.0)


def test_entropy_monitor_no_spike_on_stable_traffic():
    monitor = ai_engine.EntropyMonitor(history_size=10, spike_threshold=0.35)
    for _ in range(10):
        is_spike, _ = monitor.update_and_check(3.0)
    assert not is_spike


# ------------------------------------------------------------------
# Tests : détecteur multi-dimensionnel (Isolation Forest)
# ------------------------------------------------------------------
def test_detector_not_trained_before_window():
    det = ai_engine.TrafficAnomalyDetector(contamination=0.1)
    for _ in range(TEST_TRAINING_WINDOW - 1):
        det.update({"1.1.1.1": {"pps": 15.0, "syn_ratio": 0.1, "udp_ratio": 0.02, "avg_pkt_size": 800}})
    assert not det.ready_to_train()


def test_detector_trains_at_window_threshold():
    det = ai_engine.TrafficAnomalyDetector(contamination=0.1)
    for _ in range(TEST_TRAINING_WINDOW):
        det.update({"1.1.1.1": {"pps": 15.0, "syn_ratio": 0.1, "udp_ratio": 0.02, "avg_pkt_size": 800}})
    assert det.ready_to_train()
    det.train()
    assert det.is_trained


def test_detector_flags_volumetric_flood():
    """Un flood classique (pps très élevé) doit être détecté."""
    random.seed(0)
    det = ai_engine.TrafficAnomalyDetector(contamination=0.05)
    for _ in range(TEST_TRAINING_WINDOW):
        det.update({"1.1.1.1": {
            "pps": 10 + random.random() * 10,
            "syn_ratio": 0.05 + random.random() * 0.1,
            "udp_ratio": 0.02 + random.random() * 0.05,
            "avg_pkt_size": 750 + random.random() * 100,
        }})
    det.train()

    anomalies = det.detect({
        "1.1.1.1": {"pps": 15, "syn_ratio": 0.1, "udp_ratio": 0.03, "avg_pkt_size": 800},
        "9.9.9.9": {"pps": 50000, "syn_ratio": 0.9, "udp_ratio": 0.05, "avg_pkt_size": 60},
    })
    assert "9.9.9.9" in anomalies
    assert "1.1.1.1" not in anomalies


def test_detector_flags_stealthy_syn_flood_via_syn_ratio():
    """
    Point clé de la détection multi-critères : une attaque avec un débit
    quasi-normal (pps proche du trafic légitime) mais un syn_ratio et une
    taille de paquet très atypiques doit tout de même être détectée --
    ce qu'une détection mono-critère (pps seul) manquerait.
    """
    random.seed(1)
    det = ai_engine.TrafficAnomalyDetector(contamination=0.05)
    for _ in range(TEST_TRAINING_WINDOW):
        det.update({"1.1.1.1": {
            "pps": 15 + random.random() * 5,
            "syn_ratio": 0.05 + random.random() * 0.1,
            "udp_ratio": 0.02 + random.random() * 0.05,
            "avg_pkt_size": 750 + random.random() * 100,
        }})
    det.train()

    anomalies = det.detect({
        "1.1.1.1": {"pps": 16, "syn_ratio": 0.1, "udp_ratio": 0.03, "avg_pkt_size": 800},   # normal
        "9.9.9.9": {"pps": 18, "syn_ratio": 0.98, "udp_ratio": 0.0, "avg_pkt_size": 60},    # flood furtif
    })
    assert "9.9.9.9" in anomalies
    assert "1.1.1.1" not in anomalies


def test_detector_flags_stealthy_udp_flood_via_udp_ratio():
    """Un UDP flood à débit quasi-normal mais udp_ratio très atypique doit
    être détecté -- couverture explicite du vecteur UDP flood mentionné
    dans le cahier des charges initial (SYN/UDP Flood)."""
    random.seed(2)
    det = ai_engine.TrafficAnomalyDetector(contamination=0.05)
    for _ in range(TEST_TRAINING_WINDOW):
        det.update({"1.1.1.1": {
            "pps": 15 + random.random() * 5,
            "syn_ratio": 0.05 + random.random() * 0.1,
            "udp_ratio": 0.02 + random.random() * 0.05,
            "avg_pkt_size": 750 + random.random() * 100,
        }})
    det.train()

    anomalies = det.detect({
        "1.1.1.1": {"pps": 16, "syn_ratio": 0.1, "udp_ratio": 0.03, "avg_pkt_size": 800},   # normal
        "9.9.9.9": {"pps": 20, "syn_ratio": 0.0, "udp_ratio": 0.95, "avg_pkt_size": 70},    # UDP flood
    })
    assert "9.9.9.9" in anomalies
    assert "1.1.1.1" not in anomalies


def test_detector_sliding_window_caps_history_per_ip():
    """La fenêtre glissante ne doit jamais dépasser MAX_HISTORY_PER_IP
    échantillons par IP (nécessaire pour un ré-entraînement périodique
    qui reflète le trafic RÉCENT, pas tout l'historique depuis le
    démarrage)."""
    det = ai_engine.TrafficAnomalyDetector()
    for _ in range(TEST_MAX_HISTORY_PER_IP + 100):
        det.update({"1.1.1.1": {"pps": 1, "syn_ratio": 0, "udp_ratio": 0, "avg_pkt_size": 100}})
    assert len(det.feature_history["1.1.1.1"]) == TEST_MAX_HISTORY_PER_IP


def test_detector_due_for_retrain_respects_interval():
    """Le modèle doit être signalé comme dû pour un ré-entraînement
    seulement après l'intervalle configuré (concept drift)."""
    det = ai_engine.TrafficAnomalyDetector()
    for _ in range(TEST_TRAINING_WINDOW):
        det.update({"1.1.1.1": {"pps": 15, "syn_ratio": 0.1, "udp_ratio": 0.02, "avg_pkt_size": 800}})
    det.train()

    now = det.last_train_time
    assert not det.due_for_retrain(now, interval_sec=300)
    assert not det.due_for_retrain(now + 299, interval_sec=300)
    assert det.due_for_retrain(now + 301, interval_sec=300)


def test_detector_not_trained_never_due_for_retrain():
    det = ai_engine.TrafficAnomalyDetector()
    assert not det.due_for_retrain(9999999999, interval_sec=300)


def test_detector_explain_identifies_most_atypical_feature():
    random.seed(1)
    det = ai_engine.TrafficAnomalyDetector(contamination=0.05)
    for _ in range(TEST_TRAINING_WINDOW):
        det.update({"1.1.1.1": {
            "pps": 15 + random.random() * 5,
            "syn_ratio": 0.05 + random.random() * 0.1,
            "udp_ratio": 0.02 + random.random() * 0.05,
            "avg_pkt_size": 750 + random.random() * 100,
        }})
    det.train()
    anomalies = det.detect({"9.9.9.9": {"pps": 18, "syn_ratio": 0.98, "udp_ratio": 0.0, "avg_pkt_size": 60}})
    explanation = det.explain("9.9.9.9", anomalies["9.9.9.9"])
    assert "syn_ratio" in explanation


def test_detector_empty_input_returns_no_anomalies():
    det = ai_engine.TrafficAnomalyDetector()
    assert det.detect({}) == {}


# ------------------------------------------------------------------
# Tests : configuration externe (config.yaml), mode dry-run, whitelist
# ------------------------------------------------------------------
CONFIG_EXAMPLE_PATH = Path(__file__).resolve().parent.parent / "config" / "example.yaml"


def test_load_config_from_real_file():
    cfg = ai_engine.load_config(str(CONFIG_EXAMPLE_PATH))
    assert cfg["interface"] == "eth1"
    assert cfg["blacklist"]["dry_run"] is True
    assert "10.0.2.1" in cfg["blacklist"]["whitelist"]


def test_load_config_none_returns_defaults():
    cfg = ai_engine.load_config(None)
    assert cfg == ai_engine.DEFAULT_CONFIG
    assert cfg["blacklist"]["dry_run"] is False


def test_deep_merge_partial_override_keeps_other_defaults():
    merged = ai_engine._deep_merge(ai_engine.DEFAULT_CONFIG, {"blacklist": {"ttl_sec": 999}})
    assert merged["blacklist"]["ttl_sec"] == 999
    # Les clés non mentionnées dans l'override restent aux valeurs par défaut
    assert merged["blacklist"]["dry_run"] == ai_engine.DEFAULT_CONFIG["blacklist"]["dry_run"]
    assert merged["detection"]["contamination"] == ai_engine.DEFAULT_CONFIG["detection"]["contamination"]


class _FakeArgs:
    """Simule argparse.Namespace pour tester build_settings() sans CLI réelle."""
    def __init__(self, **kwargs):
        defaults = dict(config=None, iface=None, ttl=None, retrain_interval=None,
                         dashboard_port=None, no_dashboard=False, dry_run=False)
        defaults.update(kwargs)
        for k, v in defaults.items():
            setattr(self, k, v)


def test_build_settings_config_file_provides_defaults():
    args = _FakeArgs(config=str(CONFIG_EXAMPLE_PATH))
    settings = ai_engine.build_settings(args)
    assert settings["iface"] == "eth1"
    assert settings["dry_run"] is True
    assert "10.0.2.1" in settings["whitelist"]


def test_build_settings_cli_overrides_config_file():
    """Les arguments CLI explicites doivent primer sur le fichier de config."""
    args = _FakeArgs(config=str(CONFIG_EXAMPLE_PATH), ttl=999)
    settings = ai_engine.build_settings(args)
    assert settings["ttl"] == 999          # override CLI
    assert settings["iface"] == "eth1"     # vient toujours du fichier


def test_build_settings_dry_run_flag_forces_simulation():
    """--dry-run en CLI doit activer le mode simulation même si absent
    (ou à false) dans le fichier de config."""
    args = _FakeArgs(iface="eth1", dry_run=True)
    settings = ai_engine.build_settings(args)
    assert settings["dry_run"] is True


def test_build_settings_requires_interface():
    args = _FakeArgs(config=None, iface=None)
    with pytest.raises(SystemExit):
        ai_engine.build_settings(args)


def test_detector_accepts_injected_hyperparameters():
    """TrafficAnomalyDetector ne doit dépendre d'aucune constante globale
    -- tous les hyperparamètres doivent être injectables (nécessaire pour
    un fichier de config différent par déploiement)."""
    det = ai_engine.TrafficAnomalyDetector(contamination=0.1, training_window=50, max_history_per_ip=100)
    assert det.training_window == 50
    assert det.max_history_per_ip == 100
    for _ in range(50):
        det.update({"1.1.1.1": {"pps": 10, "syn_ratio": 0.1, "udp_ratio": 0.02, "avg_pkt_size": 800}})
    assert det.ready_to_train()
    det.train()
    assert det.is_trained


# ------------------------------------------------------------------
# Tests : persistance du modèle (joblib) -- round-trip réel sur disque
# ------------------------------------------------------------------
def test_model_save_and_load_roundtrip(tmp_path):
    """Un modèle sauvegardé puis rechargé (simulant un redémarrage) doit
    détecter exactement les mêmes anomalies que l'original -- vérifie un
    vrai aller-retour sur disque, pas seulement l'état en mémoire."""
    random.seed(3)
    det = ai_engine.TrafficAnomalyDetector(contamination=0.05, training_window=150, max_history_per_ip=600)
    for _ in range(150):
        det.update({"1.1.1.1": {
            "pps": 15 + random.random() * 5,
            "syn_ratio": 0.05 + random.random() * 0.1,
            "udp_ratio": 0.02 + random.random() * 0.05,
            "avg_pkt_size": 750 + random.random() * 100,
        }})
    det.train()

    model_path = str(tmp_path / "model.joblib")
    det.save(model_path)
    assert Path(model_path).exists()

    det_reloaded = ai_engine.TrafficAnomalyDetector(contamination=0.05, training_window=150, max_history_per_ip=600)
    assert not det_reloaded.is_trained
    assert det_reloaded.load(model_path) is True
    assert det_reloaded.is_trained

    flood = {"9.9.9.9": {"pps": 50000, "syn_ratio": 0.9, "udp_ratio": 0.05, "avg_pkt_size": 60}}
    assert "9.9.9.9" in det.detect(flood)
    assert "9.9.9.9" in det_reloaded.detect(flood)


def test_model_load_missing_file_returns_false():
    det = ai_engine.TrafficAnomalyDetector()
    assert det.load("/tmp/ce_fichier_n_existe_vraiment_pas_12345.joblib") is False
    assert not det.is_trained


def test_model_save_noop_when_not_trained(tmp_path):
    """save() sur un détecteur non entraîné ne doit rien écrire (pas
    d'erreur, pas de fichier vide trompeur)."""
    det = ai_engine.TrafficAnomalyDetector()
    model_path = str(tmp_path / "model.joblib")
    det.save(model_path)
    assert not Path(model_path).exists()


# ------------------------------------------------------------------
# Tests : sécurité du dashboard (bind restreint + token) -- vrais appels
# HTTP sur des serveurs réels démarrés le temps du test
# ------------------------------------------------------------------
def test_dashboard_default_binds_to_localhost_only():
    state = ai_engine.DashboardState()
    server = ai_engine.start_dashboard_server(state, port=0, bind_host="127.0.0.1", token=None)
    try:
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.shutdown()


def test_dashboard_without_token_allows_open_access():
    import urllib.request

    state = ai_engine.DashboardState()
    state.record_cycle({"1.1.1.1": {"pps": 10, "syn_ratio": 0.1, "udp_ratio": 0.01, "avg_pkt_size": 700}},
                        entropy=1.0, blacklisted_since={}, simulated_since={}, ttl=60)
    server = ai_engine.start_dashboard_server(state, port=0, bind_host="127.0.0.1", token=None)
    port = server.server_address[1]
    time.sleep(0.2)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/stats", timeout=2) as resp:
            assert resp.status == 200
    finally:
        server.shutdown()


def test_dashboard_with_token_rejects_missing_or_wrong_token():
    import urllib.request
    import urllib.error

    state = ai_engine.DashboardState()
    server = ai_engine.start_dashboard_server(state, port=0, bind_host="127.0.0.1", token="secret123")
    port = server.server_address[1]
    time.sleep(0.2)
    try:
        for bad_url in (f"http://127.0.0.1:{port}/api/stats",
                         f"http://127.0.0.1:{port}/api/stats?token=wrong"):
            try:
                urllib.request.urlopen(bad_url, timeout=2)
                assert False, f"aurait dû être rejeté : {bad_url}"
            except urllib.error.HTTPError as e:
                assert e.code == 401
    finally:
        server.shutdown()


def test_dashboard_with_token_accepts_correct_token():
    import urllib.request

    state = ai_engine.DashboardState()
    server = ai_engine.start_dashboard_server(state, port=0, bind_host="127.0.0.1", token="secret123")
    port = server.server_address[1]
    time.sleep(0.2)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/stats?token=secret123", timeout=2) as resp:
            assert resp.status == 200
    finally:
        server.shutdown()


# ------------------------------------------------------------------
# Tests : dashboard temps réel (serveur HTTP réel, sur localhost)
# ------------------------------------------------------------------
def test_dashboard_state_snapshot_reflects_updates():
    state = ai_engine.DashboardState()
    state.record_cycle(
        {"1.1.1.1": {"pps": 15.0, "syn_ratio": 0.1, "udp_ratio": 0.02, "avg_pkt_size": 800}},
        entropy=2.3,
        blacklisted_since={"9.9.9.9": time.time()},
        simulated_since={},
        ttl=60,
    )
    state.add_alert("danger", "test alert")
    snap = state.snapshot()
    assert "1.1.1.1" in snap["ips"]
    assert "9.9.9.9" in snap["blacklist"]
    assert len(snap["alerts"]) == 1


def test_dashboard_state_dry_run_mode_uses_simulated_blacklist():
    """En mode dry-run, aucune IP ne doit apparaître dans la blacklist
    RÉELLE -- seulement dans simulated_blacklist, avec le flag dry_run à
    True pour que le dashboard affiche le bandeau d'avertissement."""
    state = ai_engine.DashboardState()
    state.set_mode(dry_run=True, whitelist=["10.0.2.1"])
    state.record_cycle(
        {"9.9.9.9": {"pps": 500, "syn_ratio": 0.9, "udp_ratio": 0.0, "avg_pkt_size": 60}},
        entropy=1.0,
        blacklisted_since={},
        simulated_since={"9.9.9.9": time.time()},
        ttl=60,
    )
    snap = state.snapshot()
    assert snap["dry_run"] is True
    assert "10.0.2.1" in snap["whitelist"]
    assert "9.9.9.9" in snap["simulated_blacklist"]
    assert snap["blacklist"] == {}


def test_dashboard_http_server_serves_api_and_static_page():
    """Démarre un vrai serveur HTTP local et vérifie que l'API JSON et la
    page HTML du dashboard répondent correctement -- pas seulement un test
    de logique, un vrai aller-retour réseau sur localhost."""
    import urllib.request
    import json as json_module

    state = ai_engine.DashboardState()
    state.record_cycle(
        {"1.1.1.1": {"pps": 10.0, "syn_ratio": 0.05, "udp_ratio": 0.01, "avg_pkt_size": 700}},
        entropy=1.5, blacklisted_since={}, simulated_since={}, ttl=60,
    )
    server = ai_engine.start_dashboard_server(state, port=0)
    port = server.server_address[1]
    time.sleep(0.2)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/stats", timeout=2) as resp:
            data = json_module.loads(resp.read())
        assert "1.1.1.1" in data["ips"]
        assert data["feature_names"] == ai_engine.FEATURE_NAMES

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as resp:
            html = resp.read().decode()
        assert "Dashboard" in html or "dashboard" in html.lower()
    finally:
        server.shutdown()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
