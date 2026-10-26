"""
firebase_client.py — Firestore link for CyberSentinel
====================================================
The engine is the only writer of threats, stats and audit entries. It uses the
Firebase Admin SDK with a service-account key, which bypasses security rules.

Collections (PART_B_CLOUD_LOGIN_AI.md section 4):
  threats/{id}   one document per detection (the threat record + explanation)
  stats/live     counters, written about once a minute; updated_at is the engine's heartbeat
  commands/{id}  unblock requests created by an admin on the dashboard; the engine executes them
  audit/{id}     who blocked or unblocked what, and when

Nothing here may slow down or stop detection: every write runs on a background
thread, every failure is logged and swallowed, and with no key file or no
network the engine simply carries on without the cloud.

Setup: save the service-account key as python-engine/serviceAccountKey.json
(gitignored), or point the FIREBASE_CRED environment variable at it.
"""

import ipaddress
import logging
import os
import queue
import threading
import time
from datetime import datetime, timezone

from config import (
    ACTIVE_MODEL, DETECT_ONLY, FIREBASE_CRED, FIRESTORE_COLLECTION, STATS_DOCUMENT,
    STATS_CLOUD_INTERVAL, COMMAND_MAX_AGE, CLOUD_QUEUE_MAXSIZE,
)

logger = logging.getLogger("cybersentinel.firebase")

USERS, STATS, COMMANDS, AUDIT = "users", "stats", "commands", "audit"
PENDING, DONE, FAILED = "pending", "done", "failed"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch(value) -> float | None:
    """A Firestore timestamp (a datetime) → epoch seconds; anything else → None."""
    return value.timestamp() if isinstance(value, datetime) else None


class CloudStore:
    """
    Queues Firestore writes and runs them on one background thread.

    `db` is a Firestore client (or a fake in tests). `unblock` removes a firewall
    rule and returns True on success. `server_timestamp` is the SDK's sentinel.
    """

    def __init__(self, db, *, unblock=lambda ip: False, clock=time.time, server_timestamp=None,
                 pending_filter=None, stats_interval: float = STATS_CLOUD_INTERVAL,
                 command_max_age: float = COMMAND_MAX_AGE, queue_size: int = CLOUD_QUEUE_MAXSIZE,
                 detect_only: bool = DETECT_ONLY, model_version: str = ACTIVE_MODEL):
        self.db = db
        self.unblock = unblock
        self.clock = clock
        self.server_timestamp = server_timestamp
        self.pending_filter = pending_filter
        self.stats_interval = stats_interval
        self.command_max_age = command_max_age
        self.detect_only = detect_only
        self.model_version = model_version
        self._jobs: queue.Queue = queue.Queue(maxsize=queue_size)
        self._last_stats = None          # time of the last stats write
        self._watch = None
        self._thread = None
        self._stopping = threading.Event()

    # ── background worker ─────────────────────────────────────────────────────

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True, name="CloudWriter")
        self._thread.start()

    def _run(self) -> None:
        while not self._stopping.is_set() or not self._jobs.empty():
            try:
                job = self._jobs.get(timeout=0.5)
            except queue.Empty:
                continue
            self._execute(job)

    def _execute(self, job) -> None:
        name, fn = job
        try:
            fn()
        except Exception as e:                       # the cloud must never break detection
            logger.warning(f"[FIREBASE] {name} failed: {e}")

    def _submit(self, name: str, fn) -> bool:
        try:
            self._jobs.put_nowait((name, fn))
            return True
        except queue.Full:
            logger.warning(f"[FIREBASE] write queue full; dropped {name}")
            return False

    def drain(self) -> int:
        """Run everything queued, on the calling thread. Used by tests and by stop()."""
        done = 0
        while True:
            try:
                job = self._jobs.get_nowait()
            except queue.Empty:
                return done
            self._execute(job)
            done += 1

    def stop(self, timeout: float = 5.0) -> None:
        if self._watch is not None:
            try:
                self._watch.unsubscribe()
            except Exception:
                pass
        self._stopping.set()
        if self._thread is not None:
            self._thread.join(timeout)

    # ── threats ───────────────────────────────────────────────────────────────

    def store_threat(self, threat: dict) -> str | None:
        """Queue one threat record. Returns its document ID straight away."""
        ref = self.db.collection(FIRESTORE_COLLECTION).document()     # ID is generated locally
        doc = {**threat, "created_at": self.server_timestamp}
        return ref.id if self._submit("store threat", lambda: ref.set(doc)) else None

    def update_explanation(self, doc_id: str, explanation: dict) -> None:
        ref = self.db.collection(FIRESTORE_COLLECTION).document(doc_id)
        self._submit("store explanation", lambda: ref.update({"explanation": explanation}))

    # ── stats and heartbeat ───────────────────────────────────────────────────

    def update_stats(self, snapshot: dict, force: bool = False) -> bool:
        """
        Write stats/live, at most once every `stats_interval` seconds unless forced.
        `snapshot` is detector.Stats.snapshot(). Returns True when a write was queued.
        """
        now = self.clock()
        if not force and self._last_stats is not None and now - self._last_stats < self.stats_interval:
            return False
        self._last_stats = now
        doc = {
            "total_packets": snapshot.get("totalPackets", 0),
            "total_flows":   snapshot.get("totalFlows", 0),
            "total_attacks": snapshot.get("totalAttacks", 0),
            "blocked_ips":   snapshot.get("blockedIPs", 0),
            "detect_only":   self.detect_only,
            "model_version": self.model_version,
            "updated_at":    self.server_timestamp,
        }
        ref = self.db.collection(STATS).document(STATS_DOCUMENT)
        return self._submit("update stats", lambda: ref.set(doc))

    # ── audit ─────────────────────────────────────────────────────────────────

    def write_audit(self, event: str, ip: str | None = None, *, actor: str = "engine",
                    actor_email: str | None = None, detail: str = "") -> None:
        doc = {
            "timestamp":   _iso(self.clock()),
            "created_at":  self.server_timestamp,
            "actor":       actor,
            "actor_email": actor_email,
            "event":       event,
            "ip":          ip,
            "detail":      detail,
        }
        ref = self.db.collection(AUDIT).document()
        self._submit(f"audit {event}", lambda: ref.set(doc))

    # ── unblock commands ──────────────────────────────────────────────────────

    def listen_for_commands(self) -> None:
        """Watch commands with status "pending" and queue each one for handling."""
        query = self.db.collection(COMMANDS)
        query = query.where(filter=self.pending_filter) if self.pending_filter is not None \
            else query.where("status", "==", PENDING)

        def on_snapshot(snapshots, changes, read_time):
            for change in changes:
                if getattr(change.type, "name", str(change.type)) != "ADDED":
                    continue
                doc = change.document
                data = doc.to_dict() or {}
                created = _epoch(getattr(doc, "create_time", None))
                self._submit("unblock command",
                             lambda i=doc.id, d=data, c=created: self.handle_command(i, d, c))

        self._watch = query.on_snapshot(on_snapshot)

    def handle_command(self, cmd_id: str, data: dict, created: float | None = None) -> str:
        """
        Carry out one command and record the outcome. Returns the final status.
        The requester's role is checked here as well as in the security rules.
        """
        ref = self.db.collection(COMMANDS).document(cmd_id)
        uid = data.get("requested_by")
        ip_text = data.get("ip")

        def finish(status: str, message: str, email=None, ip=None) -> str:
            ref.update({"status": status, "message": message, "completed_at": self.server_timestamp})
            event = "unblock" if status == DONE else "unblock_failed"
            self.write_audit(event, ip or (ip_text if isinstance(ip_text, str) else None),
                             actor=uid or "unknown", actor_email=email, detail=message)
            logger.info(f"[COMMAND] {cmd_id}: {status} — {message}")
            return status

        if data.get("status") != PENDING:
            return data.get("status") or FAILED          # already handled; leave it alone

        requested = _epoch(data.get("requested_at")) or created
        if requested is not None and self.clock() - requested > self.command_max_age:
            return finish(FAILED, "Request expired before the engine saw it")

        if data.get("action") != "unblock":
            return finish(FAILED, f"Unknown action {data.get('action')!r}")

        if not isinstance(uid, str) or not uid:
            return finish(FAILED, "Request has no requester")
        user = self.db.collection(USERS).document(uid).get()
        profile = (user.to_dict() or {}) if user.exists else {}
        email = profile.get("email")
        if profile.get("role") != "admin":
            return finish(FAILED, "Requester is not an admin", email)

        try:
            ip = str(ipaddress.ip_address(ip_text.strip()))
        except (ValueError, AttributeError):
            return finish(FAILED, "Not a valid IP address", email)

        if not self.unblock(ip):
            return finish(FAILED, "No firewall rule was removed (none exists, or the engine lacks Administrator rights)",
                          email, ip)

        for doc in self.db.collection(FIRESTORE_COLLECTION).where("src_ip", "==", ip) \
                         .where("action", "==", "blocked").stream():
            doc.reference.update({"action": "unblocked", "unblocked_by": uid,
                                  "unblocked_at": self.server_timestamp})
        return finish(DONE, f"Firewall rule for {ip} removed", email, ip)


def connect(unblock=lambda ip: False, detect_only: bool = DETECT_ONLY) -> CloudStore | None:
    """
    Open Firestore with the service-account key. Returns None, after logging why,
    when the key is missing or the SDK cannot start; the engine then runs without the cloud.
    """
    if not os.path.exists(FIREBASE_CRED):
        logger.warning(f"[FIREBASE] No key at '{FIREBASE_CRED}'. Running without Firestore.")
        return None
    try:
        import firebase_admin
        from firebase_admin import credentials, firestore
        from google.cloud.firestore_v1.base_query import FieldFilter

        if not firebase_admin._apps:
            firebase_admin.initialize_app(credentials.Certificate(FIREBASE_CRED))
        store = CloudStore(
            firestore.client(), unblock=unblock, detect_only=detect_only,
            server_timestamp=firestore.SERVER_TIMESTAMP,
            pending_filter=FieldFilter("status", "==", PENDING),
        )
    except Exception as e:
        logger.error(f"[FIREBASE] Could not start: {e}. Running without Firestore.")
        return None
    logger.info("[FIREBASE] Connected to Firestore")
    return store
