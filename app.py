"""
Maya accounts + key generator, Vercel root app.py (WSGI). No api/ folder needed.

Environment variables (Vercel dashboard):
  ADMIN_TOKEN, UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
Routes: /  and /admin.html (admin page), /api/... (JSON API used by the APK and the admin page)
Rules: one username/password = one login. One key = one login. Time = what the admin set.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import urllib.request
from urllib.parse import urlparse, parse_qs

UPSTASH_URL = os.environ.get("UPSTASH_REDIS_REST_URL", "")
UPSTASH_TOKEN = os.environ.get("UPSTASH_REDIS_REST_TOKEN", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
HERE = os.path.dirname(os.path.abspath(__file__))

DAY = 86_400_000
UNIT_MS = {"minutes": 60_000, "hours": 3_600_000, "days": 86_400_000}
USER_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
KEY_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


# ---------- storage (Upstash Redis REST) ----------
def redis_cmd(args):
    if not UPSTASH_URL or not UPSTASH_TOKEN:
        raise RuntimeError("UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN set nahi hain")
    req = urllib.request.Request(
        UPSTASH_URL, data=json.dumps(args).encode("utf-8"), method="POST",
        headers={"Authorization": "Bearer " + UPSTASH_TOKEN, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        j = json.loads(r.read().decode("utf-8"))
    if j.get("error"):
        raise RuntimeError(j["error"])
    return j.get("result")


def get_json(key):
    v = redis_cmd(["GET", key])
    return json.loads(v) if v else None


def set_json(key, obj):
    redis_cmd(["SET", key, json.dumps(obj)])


# ---------- helpers ----------
def now_ms():
    return int(time.time() * 1000)


def hash_password(password, salt_hex):
    # same parameters as the Node version, so old accounts keep working
    return hashlib.scrypt(password.encode("utf-8"), salt=salt_hex.encode("utf-8"),
                          n=16384, r=8, p=1, dklen=64).hex()


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def make_key():
    part = lambda: "".join(secrets.choice(KEY_CHARS) for _ in range(4))
    return "MAYA-" + part() + "-" + part() + "-" + part()


def create_account(username, password, expires):
    salt = secrets.token_hex(16)
    set_json("acc:" + username, {"hash": hash_password(password, salt), "salt": salt,
                                 "expires_at": expires, "disabled": False, "used": False,
                                 "created_at": now_ms()})
    redis_cmd(["SADD", "accounts", username])


def expiry_from(kind, value):
    if kind == "lifetime":
        return now_ms() + 100 * 365 * DAY
    if kind in UNIT_MS and value > 0:
        return now_ms() + value * UNIT_MS[kind]
    return None


def is_admin(headers):
    if not ADMIN_TOKEN:
        return False
    return hmac.compare_digest(headers.get("x-admin-token", "").encode("utf-8"), ADMIN_TOKEN.encode("utf-8"))


# ---------- routes ----------
def route_get(path, headers):
    if path == "/api/health":
        return 200, {"ok": True, "service": "maya-accounts"}
    if path == "/api/update":
        return 200, get_json("cfg:update") or {"version": 0, "apk_url": "", "notes": ""}
    if path == "/api/admin/accounts":
        if not is_admin(headers):
            return 401, {"ok": False, "message": "admin token galat"}
        out = []
        for u in sorted(redis_cmd(["SMEMBERS", "accounts"]) or []):
            r = get_json("acc:" + u) or {}
            exp = r.get("expires_at", 0)
            out.append({"username": u, "expires_at": exp, "disabled": bool(r.get("disabled")),
                        "used": bool(r.get("used")), "left_min": max(0, int((exp - now_ms()) / 60000))})
        return 200, {"ok": True, "accounts": out}
    return 404, {"ok": False, "message": "Not Found"}


def route_post(path, b, headers):
    if path in ("/api/admin/gen", "/api/admin/key"):
        if not is_admin(headers):
            return 401, {"ok": False, "message": "admin token galat"}
        kind = str(b.get("type", "days"))
        value = int(b.get("value") or 0)
        expires = expiry_from(kind, value)
        if expires is None:
            return 400, {"ok": False, "message": "type lifetime/minutes/hours/days aur value > 0 do"}
        username = "u" + secrets.token_hex(4)
        password = secrets.token_urlsafe(8)
        create_account(username, password, expires)
        key = make_key()
        set_json("gkey:" + sha(key), {"username": username})
        return 200, {"ok": True, "key": key, "username": username, "password": password,
                     "type": kind, "expires_at": expires}

    if path == "/api/login_key":
        key = str(b.get("key", "")).strip().upper()
        link = get_json("gkey:" + sha(key)) if key else None
        acc = get_json("acc:" + link["username"]) if link else None
        if not acc:
            return 200, {"ok": False, "message": "Key galat hai"}
        if acc.get("disabled"):
            return 200, {"ok": False, "message": "Ye key band hai"}
        if acc.get("used"):
            return 200, {"ok": False, "message": "Ye key pehle hi use ho chuki hai"}
        if now_ms() > acc["expires_at"]:
            return 200, {"ok": False, "message": "Key ki time khatam ho gayi"}
        acc["used"] = True
        set_json("acc:" + link["username"], acc)
        return 200, {"ok": True, "username": link["username"], "expires_at": acc["expires_at"],
                     "message": "Key se login ho gaya"}

    if path == "/api/login":
        username = str(b.get("username", "")).strip().lower()
        password = str(b.get("password", ""))
        bad = {"ok": False, "message": "Username ya password galat"}
        acc = get_json("acc:" + username) if USER_RE.match(username) else None
        if not acc:
            return 200, bad
        if not hmac.compare_digest(hash_password(password, acc["salt"]), acc["hash"]):
            return 200, bad
        if acc.get("disabled"):
            return 200, {"ok": False, "message": "Ye account band hai. Admin se baat karo"}
        if now_ms() > acc["expires_at"]:
            return 200, {"ok": False, "message": "Account ki time khatam ho gayi. Admin se baat karo"}
        if acc.get("used"):
            return 200, {"ok": False, "message": "Ye username/password pehle hi use ho chuka hai. Admin se naya account lo"}
        acc["used"] = True
        set_json("acc:" + username, acc)
        return 200, {"ok": True, "username": username, "expires_at": acc["expires_at"], "message": "Login ho gaya"}

    if path == "/api/admin/account":
        if not is_admin(headers):
            return 401, {"ok": False, "message": "admin token galat"}
        username = str(b.get("username", "")).strip().lower()
        password = str(b.get("password", ""))
        if not USER_RE.match(username) or len(password) < 6:
            return 400, {"ok": False, "message": "username 3-32 (a-z, 0-9, _ . -) aur password 6+ chahiye"}
        value = int(b.get("duration_value") or 0)
        unit = b.get("duration_unit") if b.get("duration_unit") in UNIT_MS else "days"
        if value <= 0:
            return 400, {"ok": False, "message": "duration galat"}
        expires = now_ms() + value * UNIT_MS[unit]
        create_account(username, password, expires)
        return 200, {"ok": True, "username": username, "expires_at": expires}

    if path == "/api/admin/account_action":
        if not is_admin(headers):
            return 401, {"ok": False, "message": "admin token galat"}
        username = str(b.get("username", "")).strip().lower()
        action = str(b.get("action", ""))
        if action == "delete":
            redis_cmd(["DEL", "acc:" + username])
            redis_cmd(["SREM", "accounts", username])
            return 200, {"ok": True}
        acc = get_json("acc:" + username)
        if not acc:
            return 404, {"ok": False, "message": "account nahi mila"}
        if action == "disable":
            acc["disabled"] = True
        elif action == "enable":
            acc["disabled"] = False
        elif action in ("reset_use", "reset_device"):
            acc["used"] = False
        elif action == "extend":
            value = int(b.get("duration_value") or 0)
            unit = b.get("duration_unit") if b.get("duration_unit") in UNIT_MS else "days"
            if value <= 0:
                return 400, {"ok": False, "message": "duration galat"}
            acc["expires_at"] = max(now_ms(), acc["expires_at"]) + value * UNIT_MS[unit]
        else:
            return 400, {"ok": False, "message": "action galat"}
        set_json("acc:" + username, acc)
        return 200, {"ok": True, "expires_at": acc["expires_at"], "disabled": bool(acc.get("disabled"))}

    if path == "/api/admin/update":
        if not is_admin(headers):
            return 401, {"ok": False, "message": "admin token galat"}
        u = {"version": int(b.get("version") or 0), "apk_url": str(b.get("apk_url", "")), "notes": str(b.get("notes", ""))}
        set_json("cfg:update", u)
        return 200, {"ok": True, "update": u}

    return 404, {"ok": False, "message": "Not Found"}


# ---------- WSGI entry point (Vercel runs `app`) ----------
def app(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/") or "/"
    headers = {"x-admin-token": environ.get("HTTP_X_ADMIN_TOKEN", "")}
    cors = [("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Headers", "Content-Type, x-admin-token"),
            ("Access-Control-Allow-Methods", "GET, POST, OPTIONS")]

    if method == "OPTIONS":
        start_response("200 OK", [("Content-Type", "application/json")] + cors)
        return [b"{}"]

    if method == "GET" and path in ("/", "/admin.html"):
        with open(os.path.join(HERE, "admin.html"), "rb") as f:
            data = f.read()
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8")])
        return [data]

    try:
        if method == "GET":
            code, obj = route_get(path, headers)
        elif method == "POST":
            n = int(environ.get("CONTENT_LENGTH") or 0)
            raw = environ["wsgi.input"].read(n) if n > 0 else b"{}"
            try:
                b = json.loads(raw or b"{}")
            except Exception:
                b = {}
            code, obj = route_post(path, b, headers)
        else:
            code, obj = 405, {"ok": False, "message": "method nahi chalta"}
    except Exception as e:
        code, obj = 500, {"ok": False, "message": str(e)}

    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    status = {200: "200 OK", 400: "400 Bad Request", 401: "401 Unauthorized", 404: "404 Not Found",
              405: "405 Method Not Allowed", 500: "500 Internal Server Error"}.get(code, str(code))
    start_response(status, [("Content-Type", "application/json; charset=utf-8"),
                            ("Content-Length", str(len(body)))] + cors)
    return [body]
