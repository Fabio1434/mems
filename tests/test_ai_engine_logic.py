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
    prev = {"1.1.1.1": {"packets": 100, "bytes": 10000, "syn_count": 5}}
    curr = {
        "1.1.1.1": {"packets": 300, "bytes": 30000, "syn_count": 10},
        "9.9.9.9": {"packets": 5000, "bytes": 300000, "syn_count": 4990},
    }
    feats = ai_engine.extract_features(prev, curr, elapsed_sec=2.0)

    assert feats["1.1.1.1"]["pps"] == pytest.approx(100.0)
    assert feats["1.1.1.1"]["avg_pkt_size"] == pytest.approx(100.0)  # (30000-10000)/(300-100)

    # 9.9.9.9 est une nouvelle IP (absente de `prev`) : signature de SYN flood
    assert feats["9.9.9.9"]["pps"] == pytest.approx(2500.0)
    assert feats["9.9.9.9"]["syn_ratio"] == pytest.approx(4990 / 5000)


def test_extract_features_no_packets_no_division_by_zero():
    prev = {"1.1.1.1": {"packets": 100, "bytes": 1000, "syn_count": 0}}
    curr = {"1.1.1.1": {"packets": 100, "bytes": 1000, "syn_count": 0}}  # aucun nouveau paquet
    feats = ai_engine.extract_features(prev, curr, elapsed_sec=2.0)
    assert feats["1.1.1.1"]["pps"] == 0.0
    assert feats["1.1.1.1"]["syn_ratio"] == 0.0
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
    for _ in range(ai_engine.TRAINING_WINDOW - 1):
        det.update({"1.1.1.1": {"pps": 15.0, "syn_ratio": 0.1, "avg_pkt_size": 800}})
    assert not det.ready_to_train()


def test_detector_trains_at_window_threshold():
    det = ai_engine.TrafficAnomalyDetector(contamination=0.1)
    for _ in range(ai_engine.TRAINING_WINDOW):
        det.update({"1.1.1.1": {"pps": 15.0, "syn_ratio": 0.1, "avg_pkt_size": 800}})
    assert det.ready_to_train()
    det.train()
    assert det.is_trained


def test_detector_flags_volumetric_flood():
    """Un flood classique (pps très élevé) doit être détecté."""
    random.seed(0)
    det = ai_engine.TrafficAnomalyDetector(contamination=0.05)
    for _ in range(ai_engine.TRAINING_WINDOW):
        det.update({"1.1.1.1": {
            "pps": 10 + random.random() * 10,
            "syn_ratio": 0.05 + random.random() * 0.1,
            "avg_pkt_size": 750 + random.random() * 100,
        }})
    det.train()

    anomalies = det.detect({
        "1.1.1.1": {"pps": 15, "syn_ratio": 0.1, "avg_pkt_size": 800},
        "9.9.9.9": {"pps": 50000, "syn_ratio": 0.9, "avg_pkt_size": 60},
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
    for _ in range(ai_engine.TRAINING_WINDOW):
        det.update({"1.1.1.1": {
            "pps": 15 + random.random() * 5,
            "syn_ratio": 0.05 + random.random() * 0.1,
            "avg_pkt_size": 750 + random.random() * 100,
        }})
    det.train()

    anomalies = det.detect({
        "1.1.1.1": {"pps": 16, "syn_ratio": 0.1, "avg_pkt_size": 800},    # normal
        "9.9.9.9": {"pps": 18, "syn_ratio": 0.98, "avg_pkt_size": 60},    # flood furtif
    })
    assert "9.9.9.9" in anomalies
    assert "1.1.1.1" not in anomalies


def test_detector_explain_identifies_most_atypical_feature():
    random.seed(1)
    det = ai_engine.TrafficAnomalyDetector(contamination=0.05)
    for _ in range(ai_engine.TRAINING_WINDOW):
        det.update({"1.1.1.1": {
            "pps": 15 + random.random() * 5,
            "syn_ratio": 0.05 + random.random() * 0.1,
            "avg_pkt_size": 750 + random.random() * 100,
        }})
    det.train()
    anomalies = det.detect({"9.9.9.9": {"pps": 18, "syn_ratio": 0.98, "avg_pkt_size": 60}})
    explanation = det.explain("9.9.9.9", anomalies["9.9.9.9"])
    assert "syn_ratio" in explanation


def test_detector_empty_input_returns_no_anomalies():
    det = ai_engine.TrafficAnomalyDetector()
    assert det.detect({}) == {}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
