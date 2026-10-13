"""
manage_users.py — create dashboard accounts and set roles
========================================================
    python python-engine/tools/manage_users.py list
    python python-engine/tools/manage_users.py add <email> <admin|viewer>
    python python-engine/tools/manage_users.py role <email> <admin|viewer>

"add" creates the login if it does not exist yet and prints a one-time link the
person opens to choose their own password. Accounts are made here (or in the
Firebase console) because the dashboard has no public sign-up.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import FIREBASE_CRED   # noqa: E402

ROLES = ("admin", "viewer")


def main() -> int:
    args = sys.argv[1:]
    if not args or args[0] not in ("list", "add", "role") or (args[0] != "list" and len(args) != 3):
        print(__doc__)
        return 2

    import firebase_admin
    from firebase_admin import auth, credentials, firestore

    firebase_admin.initialize_app(credentials.Certificate(FIREBASE_CRED))
    users = firestore.client().collection("users")

    if args[0] == "list":
        for user in auth.list_users().iterate_all():
            profile = users.document(user.uid).get()
            role = (profile.to_dict() or {}).get("role") if profile.exists else None
            print(f"{user.email or '(no email)':40s} {role or 'viewer (no profile)'}")
        return 0

    _, email, role = args
    if role not in ROLES:
        print(f"Role must be one of: {', '.join(ROLES)}")
        return 2

    try:
        user = auth.get_user_by_email(email)
        created = False
    except auth.UserNotFoundError:
        if args[0] == "role":
            print(f"No account for {email}. Use 'add' to create it.")
            return 1
        user = auth.create_user(email=email)
        created = True

    ref = users.document(user.uid)
    fields = {"email": email, "role": role}
    if not ref.get().exists:
        fields["created_at"] = firestore.SERVER_TIMESTAMP
    # "Role" with a capital R is a common typo when the document is made by hand; the app reads "role"
    ref.set({**fields, "Role": firestore.DELETE_FIELD}, merge=True)
    print(f"{email}: role set to {role}")

    if created:
        print("Account created. Send this link so they can choose a password (it works once):")
        print(auth.generate_password_reset_link(email))
    return 0


if __name__ == "__main__":
    sys.exit(main())
