"""Per-user accounts, roles and session handling.

Roles (ascending privilege):
  viewer  - read dashboards, filter, export
  analyst - viewer + import scans, edit findings/assets, manage saved views
  admin   - analyst + manage users, SLA policy and classification rules
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import secrets
import sqlite3

from fastapi import Cookie, Header, HTTPException, status

from . import config, db

ROLES = ["viewer", "analyst", "admin"]
ROLE_LEVEL = {r: i for i, r in enumerate(ROLES)}
SESSION_COOKIE = "vmt_session"
SESSION_HOURS = 12
PBKDF2_ROUNDS = 200_000


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS)
    return digest.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    try:
        calc, _ = hash_password(password, salt)
    except ValueError:
        return False
    return secrets.compare_digest(calc, password_hash or "")


def now() -> dt.datetime:
    return dt.datetime.now()


def create_user(username: str, password: str, role: str = "viewer", full_name: str = "",
                email: str = "", must_change: int = 0,
                conn: sqlite3.Connection | None = None) -> int:
    c = conn or db.get_conn()
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    if not username or not password:
        raise ValueError("username and password are required")
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    h, salt = hash_password(password)
    cur = c.execute(
        "INSERT INTO users(username,full_name,email,role,password_hash,salt,is_active,"
        "must_change,created_at) VALUES(?,?,?,?,?,?,1,?,?)",
        (username.strip().lower(), full_name, email, role, h, salt, must_change,
         now().isoformat(timespec="seconds")),
    )
    c.commit()
    return cur.lastrowid


def set_password(user_id: int, password: str, conn: sqlite3.Connection | None = None) -> None:
    if len(password) < 8:
        raise ValueError("password must be at least 8 characters")
    c = conn or db.get_conn()
    h, salt = hash_password(password)
    c.execute("UPDATE users SET password_hash=?, salt=?, must_change=0 WHERE id=?",
              (h, salt, user_id))
    c.commit()


def bootstrap_admin(conn: sqlite3.Connection | None = None) -> str | None:
    """Create the first admin account if the user table is empty."""
    c = conn or db.get_conn()
    if c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        return None
    pwd = os.environ.get("VM_TRACKER_ADMIN_PASSWORD") or ("vmt-" + secrets.token_urlsafe(9))
    create_user("admin", pwd, role="admin", full_name="Local Administrator",
                must_change=1, conn=c)
    try:
        f = config.data_dir() / "initial-admin-password.txt"
        f.write_text(
            f"VM Tracker initial administrator account\nusername: admin\npassword: {pwd}\n"
            "Change this password at first login; then delete this file.\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            os.chmod(f, 0o600)
    except OSError:
        pass
    return pwd


def login(username: str, password: str, client: str = "",
          conn: sqlite3.Connection | None = None) -> dict:
    c = conn or db.get_conn()
    row = c.execute("SELECT * FROM users WHERE username=? AND is_active=1",
                    (username.strip().lower(),)).fetchone()
    if not row or not verify_password(password, row["password_hash"], row["salt"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    token = secrets.token_urlsafe(32)
    expires = now() + dt.timedelta(hours=SESSION_HOURS)
    c.execute("INSERT INTO sessions(token,user_id,created_at,expires_at,client) VALUES(?,?,?,?,?)",
              (token, row["id"], now().isoformat(timespec="seconds"),
               expires.isoformat(timespec="seconds"), client))
    c.execute("UPDATE users SET last_login=? WHERE id=?",
              (now().isoformat(timespec="seconds"), row["id"]))
    c.commit()
    return {"token": token, "expires_at": expires.isoformat(timespec="seconds"),
            "user": public_user(row)}


def logout(token: str, conn: sqlite3.Connection | None = None) -> None:
    c = conn or db.get_conn()
    c.execute("DELETE FROM sessions WHERE token=?", (token,))
    c.commit()


def purge_expired_sessions(conn: sqlite3.Connection | None = None) -> int:
    c = conn or db.get_conn()
    cur = c.execute("DELETE FROM sessions WHERE expires_at < ?",
                    (now().isoformat(timespec="seconds"),))
    c.commit()
    return cur.rowcount


def public_user(row) -> dict:
    return {"id": row["id"], "username": row["username"], "full_name": row["full_name"],
            "email": row["email"], "role": row["role"], "is_active": row["is_active"],
            "must_change": row["must_change"], "last_login": row["last_login"]}


def user_for_token(token: str | None) -> dict | None:
    if not token:
        return None
    c = db.get_conn()
    row = c.execute(
        "SELECT u.* , s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token=? AND u.is_active=1", (token,)
    ).fetchone()
    if not row:
        return None
    if row["expires_at"] < now().isoformat(timespec="seconds"):
        logout(token, c)
        return None
    return public_user(row)


# ---- FastAPI dependencies -------------------------------------------------
async def current_user(
    vmt_session: str | None = Cookie(default=None),
    x_vmt_token: str | None = Header(default=None),
) -> dict:
    # explicit header token wins over an ambient browser cookie
    user = user_for_token(x_vmt_token or vmt_session)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    return user


def require(role: str):
    """Dependency factory: require at least `role`."""
    need = ROLE_LEVEL[role]

    async def _dep(
        vmt_session: str | None = Cookie(default=None),
        x_vmt_token: str | None = Header(default=None),
    ) -> dict:
        user = user_for_token(x_vmt_token or vmt_session)
        if not user:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
        if ROLE_LEVEL.get(user["role"], 0) < need:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"This action requires the '{role}' role")
        return user

    return _dep
