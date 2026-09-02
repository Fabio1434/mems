#!/usr/bin/env python3
"""
test_ai_engine_logic.py
Tests unitaires pour la logique "pure" de ai_engine.py : conversion IP,
calcul du débit (pps), et détection d'anomalies (Isolation Forest).

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
# Tests : calcul du débit (pps) entre deux relevés cumulatifs
# ------------------------------------------------------------------
def test_compute_pps_basic():
    prev = {"10.0.1.2": 100}
    curr = {"10.0.1.2": 300, "10.0.1.3": 50}
    pps = ai_engine.compute_pps(prev, curr, elapsed_sec=2.0)
    assert pps["10.0.1.2"] == 100.0   # (300-100)/2
    assert pps["10.0.1.3"] == 25.0    # nouvelle IP : (50-0)/2


def test_compute_pps_counter_reset_guard():
    """Si le compteur cumulatif a été remis à zéro (ex: redémarrage du
    programme XDP), le delta ne doit jamais être négatif."""
    prev = {"10.0.1.2": 500}
    curr = {"10.0.1.2": 10}
    pps = ai_engine.compute_pps(prev, curr, elapsed_sec=2.0)
    assert pps["10.0.1.2"] == 0.0


def test_compute_pps_zero_elapsed():
    prev = {"10.0.1.2": 0}
    curr = {"10.0.1.2": 100}
    pps = ai_engine.compute_pps(prev, curr, elapsed_sec=0.0)
    assert pps["10.0.1.2"] == 0.0


# ------------------------------------------------------------------
# Tests : détecteur d'anomalies (Isolation Forest)
# ------------------------------------------------------------------
def test_detector_not_trained_before_window():
    det = ai_engine.TrafficAnomalyDetector(contamination=0.1)
    for _ in range(ai_engine.TRAINING_WINDOW - 1):
        det.update({"1.1.1.1": 15.0})
    assert not det.ready_to_train()


def test_detector_trains_at_window_threshold():
    det = ai_engine.TrafficAnomalyDetector(contamination=0.1)
    for _ in range(ai_engine.TRAINING_WINDOW):
        det.update({"1.1.1.1": 15.0})
    assert det.ready_to_train()
    det.train()
    assert det.is_trained


def test_detector_flags_massive_flood_as_anomaly():
    random.seed(0)
    det = ai_engine.TrafficAnomalyDetector(contamination=0.05)
    # Trafic normal : 10-20 pps
    for _ in range(ai_engine.TRAINING_WINDOW):
        det.update({"1.1.1.1": 10 + random.random() * 10})
    det.train()

    # Un flood massif doit être détecté comme anomalie
    anomalies = det.detect({"1.1.1.1": 15, "9.9.9.9": 50000})
    assert "9.9.9.9" in anomalies


def test_detector_empty_input_returns_no_anomalies():
    det = ai_engine.TrafficAnomalyDetector()
    assert det.detect({}) == []


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
