"""
check_rules.py — verify the published Firestore security rules
=============================================================
    python python-engine/tools/check_rules.py

Run this after publishing firestore.rules in the Firebase console (Firestore →
Rules → paste → Publish). It:

  1. compares the published rules with firestore.rules in this repository;
  2. signs in as three temporary test users (an admin, a viewer and a user with
     no profile) and as nobody, and tries each kind of access the dashboard could
     attempt, checking that it is allowed or refused as designed;
  3. deletes the temporary users and documents again.

It talks to the real project, exactly as a browser would, so a pass means the
live rules behave as intended.
"""

import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import FIREBASE_CRED, REPO_ROOT   # noqa: E402

RULES_FILE = os.path.join(REPO_ROOT, "firestore.rules")
WEB_ENV = os.path.join(REPO_ROOT, "frontend", ".env")
PREFIX = "rulescheck-"                       # every temporary user and document starts with this
ADMIN, VIEWER, STRANGER = PREFIX + "admin", PREFIX + "viewer", PREFIX + "noprofile"
A, D = "allow", "deny"


def web_api_key() -> str:
    with open(WEB_ENV, encoding="utf-8") as f:
        for line in f:
            if line.startswith("VITE_FIREBASE_API_KEY="):
                return line.split("=", 1)[1].strip()
    raise SystemExit(f"VITE_FIREBASE_API_KEY not found in {WEB_ENV}")


class Client:
    """Firestore over REST as one signed-in user (or as nobody when token is None)."""

    def __init__(self, project: str, token: str | None, uid: str | None):
        self.base = f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents"
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.uid = uid

    @staticmethod
    def _fields(data: dict) -> dict:
        def value(v):
            if isinstance(v, bool):
                return {"booleanValue": v}
            if isinstance(v, int):
                return {"integerValue": str(v)}
            return {"stringValue": v}
        return {"fields": {k: value(v) for k, v in data.items()}}

    @staticmethod
    def _allowed(response) -> bool:
        if response.status_code == 403:
            return False
        if response.status_code in (200, 404):     # 404: the read was permitted, nothing there
            return True
        raise RuntimeError(f"unexpected HTTP {response.status_code}: {response.text[:300]}")

    def get(self, path):
        return self._allowed(requests.get(f"{self.base}/{path}", headers=self.headers, timeout=30))

    def list(self, collection):
        return self._allowed(requests.get(f"{self.base}/{collection}?pageSize=1", headers=self.headers, timeout=30))

    def create(self, collection, doc_id, data):
        return self._allowed(requests.post(f"{self.base}/{collection}?documentId={doc_id}", headers=self.headers,
                                           json=self._fields(data), timeout=30))

    def update(self, path, data):
        mask = "&".join(f"updateMask.fieldPaths={k}" for k in data)
        return self._allowed(requests.patch(f"{self.base}/{path}?currentDocument.exists=true&{mask}",
                                            headers=self.headers, json=self._fields(data), timeout=30))

    def delete(self, path):
        return self._allowed(requests.delete(f"{self.base}/{path}", headers=self.headers, timeout=30))

    def create_command(self, doc_id, *, server_time=True, **fields):
        """Create commands/{doc_id} the way the dashboard does, with requested_at = server time."""
        data = {"action": "unblock", "ip": "198.51.100.42", "requested_by": self.uid, "status": "pending"}
        data.update(fields)
        data = {k: v for k, v in data.items() if v is not None}
        name = f"{self.base.split('/v1/')[1]}/commands/{doc_id}"
        write = {"update": {"name": name, **self._fields(data)}, "currentDocument": {"exists": False}}
        if server_time:
            write["updateTransforms"] = [{"fieldPath": "requested_at", "setToServerValue": "REQUEST_TIME"}]
        return self._allowed(requests.post(f"{self.base}:commit", headers=self.headers,
                                           json={"writes": [write]}, timeout=30))


def compare_with_file(creds_path: str, project: str) -> bool:
    from google.auth.transport.requests import Request
    from google.oauth2 import service_account

    creds = service_account.Credentials.from_service_account_file(
        creds_path, scopes=["https://www.googleapis.com/auth/cloud-platform"])
    creds.refresh(Request())
    headers = {"Authorization": f"Bearer {creds.token}"}
    api = "https://firebaserules.googleapis.com/v1"
    release = requests.get(f"{api}/projects/{project}/releases/cloud.firestore", headers=headers, timeout=30).json()
    ruleset = requests.get(f"{api}/{release['rulesetName']}", headers=headers, timeout=30).json()
    live = ruleset["source"]["files"][0]["content"]
    with open(RULES_FILE, encoding="utf-8") as f:
        local = f.read()
    same = live.split() == local.split()          # ignore whitespace differences
    print(f"Published rules (since {release.get('updateTime', '?')[:19]}): "
          f"{'match firestore.rules' if same else 'DIFFER from firestore.rules'}")
    return same


def main() -> int:
    import firebase_admin
    from firebase_admin import auth, credentials, firestore

    app = firebase_admin.initialize_app(credentials.Certificate(FIREBASE_CRED))
    project, db, key = app.project_id, firestore.client(), web_api_key()
    same = compare_with_file(FIREBASE_CRED, project)

    def cleanup():
        for uid in (ADMIN, VIEWER, STRANGER):
            try:
                auth.delete_user(uid)
            except auth.UserNotFoundError:
                pass
            db.collection("users").document(uid).delete()
        for collection in ("threats", "commands", "audit", "stats", "secrets"):
            for doc in db.collection(collection).list_documents():
                if doc.id.startswith(PREFIX):
                    doc.delete()

    def sign_in(uid, role):
        auth.create_user(uid=uid, email=f"{uid}@example.com")
        if role:
            db.collection("users").document(uid).set({"email": f"{uid}@example.com", "role": role})
        custom = auth.create_custom_token(uid).decode()
        r = requests.post(f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={key}",
                          json={"token": custom, "returnSecureToken": True}, timeout=30)
        r.raise_for_status()
        return Client(project, r.json()["idToken"], uid)

    cleanup()                                      # in case an earlier run was interrupted
    results = []
    try:
        admin, viewer, stranger = sign_in(ADMIN, "admin"), sign_in(VIEWER, "viewer"), sign_in(STRANGER, None)
        nobody = Client(project, None, None)
        t, c, s = PREFIX + "t1", PREFIX + "c", PREFIX + "s1"
        db.collection("threats").document(t).set({"label": "DoS", "seeded": True})
        db.collection("commands").document(c + "0").set({"action": "unblock", "ip": "198.51.100.42",
                                                         "requested_by": ADMIN, "status": "pending"})

        def check(name, expect, fn):
            try:
                got = A if fn() else D
            except Exception as e:
                got = f"error: {e}"
            results.append((name, expect, got))

        # threats and stats
        check("signed-out cannot read a threat",            D, lambda: nobody.get(f"threats/{t}"))
        check("signed-out cannot list threats",             D, lambda: nobody.list("threats"))
        check("viewer reads a threat",                      A, lambda: viewer.get(f"threats/{t}"))
        check("viewer lists threats",                       A, lambda: viewer.list("threats"))
        check("user without a profile reads a threat",      A, lambda: stranger.get(f"threats/{t}"))
        check("admin cannot create a threat",               D, lambda: admin.create("threats", PREFIX + "t2", {"label": "DoS"}))
        check("admin cannot edit a threat",                 D, lambda: admin.update(f"threats/{t}", {"label": "Benign"}))
        check("admin cannot delete a threat",               D, lambda: admin.delete(f"threats/{t}"))
        check("signed-out cannot read stats",               D, lambda: nobody.get("stats/live"))
        check("viewer reads stats",                         A, lambda: viewer.get("stats/live"))
        check("viewer cannot write stats",                  D, lambda: viewer.create("stats", s, {"total_attacks": 0}))
        # users
        check("viewer reads own profile",                   A, lambda: viewer.get(f"users/{VIEWER}"))
        check("viewer cannot read another profile",         D, lambda: viewer.get(f"users/{ADMIN}"))
        check("viewer cannot list profiles",                D, lambda: viewer.list("users"))
        check("admin lists profiles",                       A, lambda: admin.list("users"))
        check("viewer cannot make themselves admin",        D, lambda: viewer.update(f"users/{VIEWER}", {"role": "admin"}))
        check("user without a profile cannot create one",   D, lambda: stranger.create("users", STRANGER, {"role": "admin"}))
        check("admin cannot set an unknown role",           D, lambda: admin.update(f"users/{VIEWER}", {"role": "owner"}))
        check("admin cannot demote themselves",             D, lambda: admin.update(f"users/{ADMIN}", {"role": "viewer"}))
        check("admin cannot delete themselves",             D, lambda: admin.delete(f"users/{ADMIN}"))
        check("admin changes another user's role",          A, lambda: admin.update(f"users/{VIEWER}", {"role": "admin"}))
        db.collection("users").document(VIEWER).set({"email": f"{VIEWER}@example.com", "role": "viewer"})
        # commands
        check("viewer cannot create an unblock request",    D, lambda: viewer.create_command(c + "1"))
        check("signed-out cannot create a request",         D, lambda: nobody.create_command(c + "2", requested_by=ADMIN))
        check("admin cannot request in another's name",     D, lambda: admin.create_command(c + "3", requested_by=VIEWER))
        check("request must start as pending",              D, lambda: admin.create_command(c + "4", status="done"))
        check("only the unblock action is accepted",        D, lambda: admin.create_command(c + "5", action="block"))
        check("request must carry an ip",                   D, lambda: admin.create_command(c + "6", ip=None))
        check("ip must be text",                            D, lambda: admin.create_command(c + "7", ip=12345))
        check("extra fields are refused",                   D, lambda: admin.create_command(c + "8", message="hi"))
        check("request needs the server's time",            D, lambda: admin.create_command(c + "9", server_time=False))
        check("admin creates an unblock request",           A, lambda: admin.create_command(c + "10"))
        check("admin cannot edit a request afterwards",     D, lambda: admin.update(f"commands/{c}0", {"status": "done"}))
        check("admin cannot delete a request",              D, lambda: admin.delete(f"commands/{c}0"))
        check("admin reads requests",                       A, lambda: admin.get(f"commands/{c}0"))
        check("viewer cannot read requests",                D, lambda: viewer.get(f"commands/{c}0"))
        # audit and everything else
        check("admin reads the audit log",                  A, lambda: admin.list("audit"))
        check("viewer cannot read the audit log",           D, lambda: viewer.list("audit"))
        check("admin cannot write the audit log",           D, lambda: admin.create("audit", PREFIX + "a1", {"event": "unblock"}))
        check("unknown collections are closed",             D, lambda: admin.get(f"secrets/{PREFIX}x"))
    finally:
        cleanup()

    failed = 0
    for name, expect, got in results:
        ok = expect == got
        failed += not ok
        print(f"  {'pass' if ok else 'FAIL'}  expected {expect:5s} got {got:5s}  {name}")
    print(f"\n{len(results) - failed} of {len(results)} access checks passed"
          + ("" if same else "  (the published rules differ from firestore.rules)"))
    return 0 if failed == 0 and same else 1


if __name__ == "__main__":
    sys.exit(main())
