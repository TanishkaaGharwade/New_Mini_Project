"""Explanations: API replies, validation, offline fallback, rate limit and reuse. No network."""

import json

import pytest

import ai
from ai import Explainer, facts_for, offline_explanation, validate

T0 = 1_760_000_000.0
GOOD = {"severity": "high", "summary": "A device tried 38 ports in 5 seconds.",
        "mechanism": "Scanning finds open services.", "recommendation": "Keep it blocked."}

THREAT = {
    "timestamp": "2026-10-12T14:03:22Z", "src_ip": "198.51.100.42", "src_port": 51544,
    "dst_ip": "192.168.1.4", "dst_port": 80, "protocol": "TCP", "label": "PortScan",
    "confidence": 0.97, "trigger": "both", "action": "blocked", "packet_count": 40,
    "evidence": [{"feature": "distinct ports in 5 s", "value": 38}],
}


class Clock:
    now = T0

    def __call__(self):
        return self.now


class Reply:
    def __init__(self, content=None, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {"choices": [{"message": {"content": content}}]}

    def json(self):
        return self._body


class Api:
    """Stands in for requests.post and records every call."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.calls = []

    def __call__(self, url, headers=None, json=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "json": json, "timeout": timeout})
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, Exception):
            raise reply
        return reply


def make(api, **kwargs):
    clock = Clock()
    stored = []
    explainer = Explainer("key-123", "some-model", post=api, clock=clock,
                          store=lambda doc_id, e: stored.append((doc_id, e)), **kwargs)
    return explainer, clock, stored


# ── the offline text ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("label", ["DoS", "DDoS", "PortScan", "BruteForce", "Botnet", "SynFlood", "IcmpFlood"])
def test_every_label_has_a_valid_offline_explanation(label):
    explanation = offline_explanation(label)
    assert explanation["source"] == "offline"
    assert validate(explanation) is not None
    assert explanation != {**ai.GENERIC, "source": "offline"}


def test_unknown_label_gets_the_generic_offline_text():
    assert offline_explanation("SomethingNew")["summary"] == ai.GENERIC["summary"]


# ── validation ────────────────────────────────────────────────────────────────

def test_validate_normalises_severity_and_trims():
    out = validate({**GOOD, "summary": "  padded  ", "extra": "ignored"})
    assert out == {**GOOD, "severity": "HIGH", "summary": "padded"}


@pytest.mark.parametrize("bad", [
    None, "text", [],
    {k: v for k, v in GOOD.items() if k != "mechanism"},
    {**GOOD, "severity": "EXTREME"},
    {**GOOD, "summary": ""},
    {**GOOD, "recommendation": 5},
])
def test_validate_rejects_replies_that_do_not_fit(bad):
    assert validate(bad) is None


def test_validate_caps_very_long_text():
    assert len(validate({**GOOD, "mechanism": "x" * 5000})["mechanism"]) == ai.MAX_TEXT


# ── what is sent ──────────────────────────────────────────────────────────────

def test_request_carries_metadata_only():
    api = Api(Reply(json.dumps(GOOD)))
    explainer, _, _ = make(api)
    explainer.explain(THREAT)

    call, = api.calls
    assert call["url"] == ai.GROQ_URL
    assert call["headers"] == {"Authorization": "Bearer key-123"}
    assert call["json"]["model"] == "some-model"
    assert call["json"]["response_format"] == {"type": "json_object"}
    sent = json.loads(call["json"]["messages"][1]["content"])
    assert sent == facts_for(THREAT)
    assert sent["evidence"] == THREAT["evidence"] and sent["label"] == "PortScan"
    assert "192.168.1.4" not in json.dumps(call["json"])        # this machine's address stays local


# ── API outcomes ──────────────────────────────────────────────────────────────

def test_good_reply_becomes_an_ai_explanation():
    explainer, _, _ = make(Api(Reply(json.dumps(GOOD))))
    assert explainer.explain(THREAT) == {**GOOD, "severity": "HIGH", "source": "ai"}


@pytest.mark.parametrize("reply", [
    Reply(status=429, body={"error": "rate limited"}),
    Reply(status=500, body={}),
    Reply("this is not json"),
    Reply(json.dumps({"severity": "HIGH"})),                     # missing fields
    Reply(body={"unexpected": True}),
    TimeoutError("slow"),
])
def test_any_api_problem_falls_back_to_offline_text(reply):
    explainer, _, _ = make(Api(reply))
    assert explainer.explain(THREAT) == offline_explanation("PortScan")


def test_without_key_or_model_the_api_is_never_called():
    api = Api(Reply(json.dumps(GOOD)))
    for key, model in ((None, "m"), ("k", None), ("", "")):
        explainer = Explainer(key, model, post=api)
        assert not explainer.online
        assert explainer.explain(THREAT)["source"] == "offline"
    assert api.calls == []


# ── reuse and rate limit ──────────────────────────────────────────────────────

def test_same_label_and_source_reuses_the_explanation():
    api = Api(Reply(json.dumps(GOOD)))
    explainer, clock, _ = make(api, reuse_seconds=120)
    first = explainer.explain(THREAT)
    clock.now += 60
    assert explainer.explain({**THREAT, "packet_count": 999}) == first
    assert len(api.calls) == 1

    clock.now += 61                                              # past the reuse window
    explainer.explain(THREAT)
    assert len(api.calls) == 2


def test_different_source_or_label_is_asked_separately():
    api = Api(Reply(json.dumps(GOOD)))
    explainer, _, _ = make(api)
    explainer.explain(THREAT)
    explainer.explain({**THREAT, "src_ip": "203.0.113.9"})
    explainer.explain({**THREAT, "label": "DoS"})
    assert len(api.calls) == 3


def test_rate_limit_switches_to_offline_until_the_minute_passes():
    api = Api(Reply(json.dumps(GOOD)))
    explainer, clock, _ = make(api, max_per_minute=3)
    sources = [f"10.0.0.{i}" for i in range(5)]
    results = [explainer.explain({**THREAT, "src_ip": ip})["source"] for ip in sources]
    assert results == ["ai", "ai", "ai", "offline", "offline"] and len(api.calls) == 3

    clock.now += 61
    assert explainer.explain({**THREAT, "src_ip": "10.0.0.9"})["source"] == "ai"


def test_offline_fallback_is_not_cached_so_the_api_is_retried():
    api = Api(Reply(status=500, body={}), Reply(json.dumps(GOOD)))
    explainer, _, _ = make(api)
    assert explainer.explain(THREAT)["source"] == "offline"
    assert explainer.explain(THREAT)["source"] == "ai"


# ── background queue ──────────────────────────────────────────────────────────

def test_request_stores_the_explanation_against_the_document():
    explainer, _, stored = make(Api(Reply(json.dumps(GOOD))))
    assert explainer.request("doc-1", THREAT) is True
    assert stored == []                                          # nothing happens on the caller's thread
    assert explainer.drain() == 1
    assert stored == [("doc-1", {**GOOD, "severity": "HIGH", "source": "ai"})]


def test_a_failing_store_does_not_raise():
    def broken(doc_id, explanation):
        raise RuntimeError("firestore down")

    explainer = Explainer("k", "m", post=Api(Reply(json.dumps(GOOD))), store=broken)
    explainer.request("doc-1", THREAT)
    assert explainer.drain() == 1


def test_full_queue_skips_instead_of_blocking():
    explainer = Explainer(None, None, queue_size=1)
    assert explainer.request("a", THREAT) is True
    assert explainer.request("b", THREAT) is False
