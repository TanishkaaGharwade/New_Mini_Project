"""
ai.py — Plain-language explanations for CyberSentinel detections
===============================================================
Each stored threat gets one explanation: severity, summary, mechanism and
recommendation. It comes from the Groq API when a key is configured, and from a
built-in offline text otherwise (or whenever the API fails or is rate-limited).

Rules:
  - Only the record's metadata is sent (label, counts, ports, evidence). Never packet contents.
  - The explanation is advisory. Nothing here decides to block or unblock.
  - A slow or failing API never delays detection: requests run on a background thread.

Configuration, in python-engine/.env:
    GROQ_API_KEY=...
    GROQ_MODEL=...        a chat model name from the Groq console
"""

import json
import logging
import os
import queue
import threading
import time
from collections import deque

import requests
from dotenv import load_dotenv

from config import (
    ENGINE_DIR, AI_TIMEOUT, AI_MAX_PER_MINUTE, AI_REUSE_SECONDS, AI_QUEUE_MAXSIZE,
)

logger = logging.getLogger("cybersentinel.ai")

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
FIELDS = ("severity", "summary", "mechanism", "recommendation")
MAX_TEXT = 600   # characters per field

# Used when the API is unavailable. Keyed by the record's label.
OFFLINE = {
    "PortScan": {
        "severity": "MEDIUM",
        "summary": "A device tried to connect to many different ports on this computer in a short time.",
        "mechanism": "Attackers scan ports to find out which services are running, the way a burglar "
                     "tries every door and window. The scan does no damage itself, but it usually comes before an attack.",
        "recommendation": "Check whether you recognise the source address. Close or firewall any service you do not need.",
    },
    "SynFlood": {
        "severity": "HIGH",
        "summary": "A device sent a very large number of connection requests without completing any of them.",
        "mechanism": "Each half-open request makes the computer reserve memory while it waits for a reply "
                     "that never comes. Enough of them leave no room for real visitors.",
        "recommendation": "Keep the source blocked. If the address is one of your own devices, check it for malware.",
    },
    "IcmpFlood": {
        "severity": "MEDIUM",
        "summary": "A device sent an unusually large number of ping messages to this computer.",
        "mechanism": "Answering each ping uses a little network capacity and processing time. "
                     "A flood of them can slow the connection down for everything else.",
        "recommendation": "Keep the source blocked while the flood continues.",
    },
    "DoS": {
        "severity": "HIGH",
        "summary": "A device sent traffic shaped to overload a service on this computer.",
        "mechanism": "Denial-of-service tools open many connections or send requests that are slow or "
                     "expensive to answer, so the service is too busy to respond to real users.",
        "recommendation": "Keep the source blocked and check that the targeted service is still responding.",
    },
    "DDoS": {
        "severity": "CRITICAL",
        "summary": "Traffic matching a distributed denial-of-service attack reached this computer.",
        "mechanism": "Many machines send requests at the same time to exhaust the target. "
                     "Blocking one source helps only a little, because others keep sending.",
        "recommendation": "Block the sources seen here and watch for more. A large attack needs filtering by the network provider.",
    },
    "BruteForce": {
        "severity": "HIGH",
        "summary": "A device made repeated login attempts against a service on this computer.",
        "mechanism": "Automated tools try many username and password combinations, hoping one is weak or reused.",
        "recommendation": "Keep the source blocked. Use strong, unique passwords and turn off remote login services you do not use.",
    },
    "Botnet": {
        "severity": "HIGH",
        "summary": "Traffic resembling an infected machine talking to its controller was seen.",
        "mechanism": "Malware on a compromised computer regularly contacts a control server for instructions. "
                     "The pattern of those short, repeated connections is what was recognised.",
        "recommendation": "Treat this as uncertain: this detection has more false alarms than the others. "
                          "Run a malware scan on the device involved.",
    },
}
GENERIC = {
    "severity": "MEDIUM",
    "summary": "Network traffic matching a known attack pattern was detected.",
    "mechanism": "The traffic's size, timing or rate differed from normal use in a way the detector associates with attacks.",
    "recommendation": "Review the source address and the evidence listed with this alert.",
}

SYSTEM_PROMPT = (
    "You explain intrusion-detection alerts to people who are not security experts. "
    "You are given one alert as JSON. Use only the facts in it; do not invent details such as "
    "tools, countries, or intent. Mention the specific evidence values when they help. "
    "Write plain, short sentences with no jargon and no markdown. "
    "The 'action' field says what the system already did: 'blocked' means the source was blocked; "
    "'alert_only' and 'detect_only' mean nothing was blocked; 'whitelisted' means the source is trusted and was not blocked. "
    "Reply with a single JSON object with exactly these keys: "
    "severity (one of LOW, MEDIUM, HIGH, CRITICAL), "
    "summary (1-2 sentences: what happened), "
    "mechanism (2-3 sentences: how this kind of attack works), "
    "recommendation (1-2 sentences: what the user should do)."
)


def offline_explanation(label: str) -> dict:
    return {**OFFLINE.get(label, GENERIC), "source": "offline"}


def facts_for(threat: dict) -> dict:
    """The metadata sent to the API: no packet contents, and this machine's own address is left out."""
    return {
        "label":        threat.get("label"),
        "confidence":   threat.get("confidence"),
        "detected_by":  threat.get("trigger"),
        "action":       threat.get("action"),
        "protocol":     threat.get("protocol"),
        "source_ip":    threat.get("src_ip"),
        "target_port":  threat.get("dst_port"),
        "packet_count": threat.get("packet_count"),
        "evidence":     threat.get("evidence", []),
    }


def validate(reply) -> dict | None:
    """A model reply → a clean explanation, or None when it does not fit the contract."""
    if not isinstance(reply, dict):
        return None
    out = {}
    for field in FIELDS:
        value = reply.get(field)
        if not isinstance(value, str) or not value.strip():
            return None
        out[field] = value.strip()[:MAX_TEXT]
    out["severity"] = out["severity"].upper()
    if out["severity"] not in SEVERITIES:
        return None
    return out


class Explainer:
    """
    explain(threat) returns an explanation at once (API or offline).
    request(doc_id, threat) queues the same work and passes the result to `store(doc_id, explanation)`.
    """

    def __init__(self, api_key: str | None = None, model: str | None = None, *, store=lambda doc_id, e: None,
                 post=requests.post, clock=time.time, timeout: float = AI_TIMEOUT,
                 max_per_minute: int = AI_MAX_PER_MINUTE, reuse_seconds: float = AI_REUSE_SECONDS,
                 queue_size: int = AI_QUEUE_MAXSIZE):
        self.api_key = api_key or None
        self.model = model or None
        self.store = store
        self.post = post
        self.clock = clock
        self.timeout = timeout
        self.max_per_minute = max_per_minute
        self.reuse_seconds = reuse_seconds
        self._calls: deque = deque()     # times of recent API calls
        self._recent: dict = {}          # (label, src_ip) → (time, explanation)
        self._jobs: queue.Queue = queue.Queue(maxsize=queue_size)
        self._thread = None
        self._stopping = threading.Event()

    @classmethod
    def from_env(cls, **kwargs) -> "Explainer":
        load_dotenv(os.path.join(ENGINE_DIR, ".env"))
        key, model = os.getenv("GROQ_API_KEY"), os.getenv("GROQ_MODEL")
        if not key:
            logger.warning("[AI] GROQ_API_KEY is not set. Using offline explanations.")
        elif not model:
            logger.warning("[AI] GROQ_MODEL is not set. Using offline explanations.")
        else:
            logger.info(f"[AI] Explanations from Groq model '{model}'")
        return cls(key, model, **kwargs)

    @property
    def online(self) -> bool:
        return bool(self.api_key and self.model)

    # ── one explanation ───────────────────────────────────────────────────────

    def explain(self, threat: dict) -> dict:
        label, now = threat.get("label"), self.clock()
        key = (label, threat.get("src_ip"))

        cached = self._recent.get(key)
        if cached is not None and now - cached[0] < self.reuse_seconds:
            return cached[1]

        explanation = self._ask(threat, now) if self.online else None
        if explanation is None:
            return offline_explanation(label)       # not cached, so the API is tried again next time
        self._recent[key] = (now, explanation)
        for old in [k for k, (t, _) in self._recent.items() if now - t >= self.reuse_seconds]:
            del self._recent[old]
        return explanation

    def _ask(self, threat: dict, now: float) -> dict | None:
        while self._calls and now - self._calls[0] >= 60:
            self._calls.popleft()
        if len(self._calls) >= self.max_per_minute:
            return None
        self._calls.append(now)
        try:
            response = self.post(
                GROQ_URL,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "temperature": 0.2,
                    "max_tokens": 1500,   # reasoning models spend part of this before the answer
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": json.dumps(facts_for(threat))},
                    ],
                },
                timeout=self.timeout,
            )
            if response.status_code != 200:
                logger.warning(f"[AI] Groq returned HTTP {response.status_code}; using offline text")
                return None
            content = response.json()["choices"][0]["message"]["content"]
            explanation = validate(json.loads(content))
        except Exception as e:
            logger.warning(f"[AI] Request failed ({type(e).__name__}); using offline text")
            return None
        if explanation is None:
            logger.warning("[AI] Reply did not match the expected format; using offline text")
            return None
        return {**explanation, "source": "ai"}

    # ── background queue ──────────────────────────────────────────────────────

    def request(self, doc_id: str, threat: dict) -> bool:
        try:
            self._jobs.put_nowait((doc_id, threat))
            return True
        except queue.Full:
            logger.warning("[AI] explanation queue full; skipped one")
            return False

    def process_one(self, doc_id: str, threat: dict) -> dict:
        explanation = self.explain(threat)
        try:
            self.store(doc_id, explanation)
        except Exception as e:
            logger.warning(f"[AI] could not store explanation: {e}")
        return explanation

    def drain(self) -> int:
        """Handle everything queued on the calling thread. Used by tests."""
        done = 0
        while True:
            try:
                doc_id, threat = self._jobs.get_nowait()
            except queue.Empty:
                return done
            self.process_one(doc_id, threat)
            done += 1

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True, name="Explainer")
        self._thread.start()

    def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                doc_id, threat = self._jobs.get(timeout=0.5)
            except queue.Empty:
                continue
            self.process_one(doc_id, threat)

    def stop(self, timeout: float = 3.0) -> None:
        self._stopping.set()
        if self._thread is not None:
            self._thread.join(timeout)
