"""Classifier tests against the real model_v1 (loads in a few seconds, no network)."""

import json
import math
import warnings

import pytest

from classifier import BENIGN_P99, ThreatClassifier
from config import FEATURES_PATH, MODEL_PATH
from feature_extractor import FlowTracker, PacketInfo, feature_vector


@pytest.fixture(scope="module")
def clf():
    return ThreatClassifier()


def test_model_matches_features_json(clf):
    with open(FEATURES_PATH, encoding="utf-8") as f:
        spec = json.load(f)
    assert MODEL_PATH.endswith("model_v1.pkl")
    assert clf.features == spec["features"] == list(clf.model.feature_names_in_)
    assert clf.classes == spec["classes"] == ["Benign", "Botnet", "BruteForce", "DDoS", "DoS", "PortScan"]
    assert set(BENIGN_P99) == set(clf.features)


def test_mismatched_feature_list_is_rejected(tmp_path):
    with open(FEATURES_PATH, encoding="utf-8") as f:
        spec = json.load(f)
    spec["features"] = list(reversed(spec["features"]))
    bad = tmp_path / "features.json"
    bad.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(ValueError):
        ThreatClassifier(features_path=str(bad))


def test_classify_real_flow_without_warnings(clf):
    tracker = FlowTracker()
    tracker.add_packet(PacketInfo(0.0, "10.0.0.5", "8.8.8.8", 53000, 53, "UDP", 40))
    tracker.add_packet(PacketInfo(0.015, "8.8.8.8", "10.0.0.5", 53, 53000, "UDP", 120))
    vector = feature_vector(tracker.flush()[0])

    with warnings.catch_warnings():
        warnings.simplefilter("error")                 # e.g. "X does not have valid feature names"
        label, confidence = clf.classify(vector)
    assert label in clf.classes
    assert 0.0 <= confidence <= 1.0


def test_nan_rates_are_accepted(clf):
    vector = [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, math.nan, math.nan, 0, 0, 0, 0, 0, 0]
    label, confidence = clf.classify(vector)
    assert label in clf.classes and 0.0 <= confidence <= 1.0


def test_classify_many_matches_single(clf):
    vectors = [[0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, math.nan, math.nan, 0, 0, 0, 0, 0, 0],
               [1000, 1, 1, 10, 40, 10, 10, 40, 40, 20, 17.32, 50000, 2000, 1000, 0, 1000, 0, 0, 1]]
    assert clf.classify_many(vectors) == [clf.classify(v) for v in vectors]


def test_wrong_vector_length_raises(clf):
    with pytest.raises(ValueError):
        clf.classify([0] * 18)


def test_evidence_lists_top_three_above_benign_p99(clf):
    vector = {name: 0.0 for name in clf.features}
    vector["Flow Packets/s"] = 3_000_000          # 3x its p99
    vector["Total Fwd Packets"] = 550             # 10x
    vector["Down/Up Ratio"] = 6                   # 2x
    vector["Flow Bytes/s"] = 17_000_000           # 1.05x
    vector["Flow IAT Mean"] = math.nan            # skipped
    vector["Packet Length Mean"] = 983            # exactly p99: not above
    ev = clf.evidence([vector[n] for n in clf.features])
    assert ev == [{"feature": "Total Fwd Packets", "value": 550},
                  {"feature": "Flow Packets/s", "value": 3_000_000},
                  {"feature": "Down/Up Ratio", "value": 6}]


def test_evidence_empty_for_ordinary_flow(clf):
    assert clf.evidence([0.0] * len(clf.features)) == []
