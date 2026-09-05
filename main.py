import os
import secrets
import string
import libsql
import hmac
import hashlib
import time
from datetime import datetime, timedelta, timezone
from html import escape

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from itsdangerous import URLSafeSerializer, BadSignature
from pydantic import BaseModel

TURSO_DATABASE_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "troque-esta-senha")
SECRET_KEY = os.environ.get("SECRET_KEY", "troque-este-secret-tambem")
# O SEGREDO AGORA É LIDO DAS VARIÁVEIS DE AMBIENTE DO RENDER
HEARTBEAT_SECRET = os.environ.get("HEARTBEAT_SECRET", "EADMT4-PRO-HEARTBEAT-2026-SECRET")

TRIAL_DAYS = 2
LICENSE_DAYS = 30
MAX_MACHINES_PER_KEY = 2

serializer = URLSafeSerializer(SECRET_KEY, salt="admin-session")

app = FastAPI(title="EADMT4-PRO License Server")

LICENSE_COLUMNS = [
    "machine_id", "machine_name", "first_seen",
    "trial_expires", "license_expires", "last_seen", "revoked", "license_key"
]
KEY_COLUMNS = ["license_key", "created", "expires", "revoked", "max_machines"]


def get_db():
    return libsql.connect(TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)


def row_to_dict(row, columns):
    if not row:
        return None
    return dict(zip(columns, row))


def now_utc():
    return datetime.now(timezone.utc)


def parse_dt(s):
    if not s:
        return None
    return datetime.fromisoformat(s)


def generate_key():
    alphabet = string.ascii_uppercase + string.digits
    part = lambda: "".join(secrets.choice(alphabet) for _ in range(4))
    return "EAD-" + part() + "-" + part() + "-" + part()


class CheckRequest(BaseModel):
    machine_id: str
    machine_name: str = ""
    license_key: str = ""


def _build_response(status: str, machine_id: str, expires_at, days_left: int):
    """Função auxiliar que garante que TODA resposta tenha a assinatura (sig) do servidor"""
    timestamp = int(time.time())
    payload_to_sign = f"{status}|{machine_id}|{timestamp}"
    
    sig = hmac.new(
        HEARTBEAT_SECRET.encode('utf-8'),
        payload_to_sign.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    exp_str = None
    if isinstance(expires_at, datetime):
        exp_str = expires_at.isoformat()
    elif isinstance(expires_at, str):
        exp_str = expires_at
        
    return {
        "status": status,
        "expires_at": exp_str,
        "days_left": max(0, int(days_left)),
        "sig": sig  # <--- AQUI ESTÁ A ASSINATURA QUE O PYTHON ESPERA
    }


@app.post("/api/check")
def check_license(payload: CheckRequest):
    conn = get_db()
    now = now_utc()
    key = (payload.license_key or "").strip().upper()

    key_row = None
    key_error = None
    if key:
        key_row = row_to_dict(
            conn.execute("SELECT * FROM license_keys WHERE license_key = ?", (key,)).fetchone(),
            KEY_COLUMNS,
        )
        if key_row is None:
            key_error = "key_invalid"
        elif key_row["revoked"]:
            key_error = "key_revoked"
        else:
            kexp = parse_dt(key_row["expires"])
            if kexp and kexp <= now:
                key_error = "key_expired"

    row = row_to_dict(
        conn.execute("SELECT * FROM licenses WHERE machine_id = ?", (payload.machine_id,)).fetchone(),
        LICENSE_COLUMNS,
    )

    if key and key_error:
        conn.close()
        return _build_response(key_error, payload.machine_id, None, 0)

    if key and key_row:
        kexp = parse_dt(key_row["expires"])
        if kexp is None:
            kexp = now + timedelta(days=LICENSE_DAYS)
            conn.execute(
                "UPDATE license_keys SET expires = ? WHERE license_key = ?",
                (kexp.isoformat(), key),
            )

        if row is None:
            count = conn.execute(
                "SELECT COUNT(*) FROM licenses WHERE license_key = ? AND revoked = 0", (key,)
            ).fetchone()[0]
            if count >= int(key_row["max_machines"] or MAX_MACHINES_PER_KEY):
                conn.commit()
                conn.close()
                return _build_response("limit", payload.machine_id, None, 0)
            
            conn.execute(
                "INSERT INTO licenses (machine_id, machine_name, first_seen, trial_expires, license_expires, last_seen, license_key) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    payload.machine_id,
                    payload.machine_name,
                    now.isoformat(),
                    (now + timedelta(days=TRIAL_DAYS)).isoformat(),
                    kexp.isoformat(),
                    now.isoformat(),
                    key,
                ),
            )
            conn.commit()
            conn.close()
            return _build_response("licensed", payload.machine_id, kexp, (kexp - now).days)

        conn.execute(
            "UPDATE licenses SET last_seen = ?, machine_name = ?, license_key = ?, license_expires = ?, revoked = 0 "
            "WHERE machine_id = ?",
            (now.isoformat(), payload.machine_name or row["machine_name"], key, kexp.isoformat(), payload.machine_id),
        )
        conn.commit()
        conn.close()
        return _build_response("licensed", payload.machine_id, kexp, (kexp - now).days)

    if row is None:
        first_seen = now
        trial_expires = now + timedelta(days=TRIAL_DAYS)
        conn.execute(
            "INSERT INTO licenses (machine_id, machine_name, first_seen, trial_expires, last_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (payload.machine_id, payload.machine_name, first_seen.isoformat(), trial_expires.isoformat(), now.isoformat()),
        )
        conn.commit()
        status = "trial"
        expires_at = trial_expires
        days_left = TRIAL_DAYS
    else:
        conn.execute(
            "UPDATE licenses SET last_seen = ?, machine_name = ? WHERE machine_id = ?",
            (now.isoformat(), payload.machine_name or row["machine_name"], payload.machine_id),
        )
        conn.commit()

        if row["revoked"]:
            status = "revoked"
            expires_at = None
            days_left = 0
        else:
            license_expires = parse_dt(row["license_expires"])
            trial_expires = parse_dt(row["trial_expires"])

            if license_expires and license_expires > now:
                status = "licensed"
                expires_at = license_expires
                days_left = (license_expires - now).days
            elif trial_expires and trial_expires > now:
                status = "trial"
                expires_at = trial_expires
                days_left = (trial_expires - now).days
            else:
                status = "expired"
                expires_at = None
                days_left = 0

    conn.close()
    return _build_response(status, payload.machine_id, expires_at, days_left)


# ----------------------------------------------------------------------
# VISUAL DO PAINEL ADMINISTRATIVO (MANTIDO EXATAMENTE COMO ESTAVA)
# ----------------------------------------------------------------------
PAGE_STYLE = """
<style>
  :root {
    --deriv-red: #ff444f;
    --deriv-red-dark: #eb3e48;
    --deriv-black: #0e0e0e;
    --deriv-gray: #6b6b6b;
    --deriv-light: #f5f7f9;
    --deriv-border: #e6e9e9;
    --deriv-green: #4caf50;
    --deriv-blue: #2196f3;
  }
  * { box-sizing: border-box; }
  body {
    font-family: 'IBM Plex Sans', 'Segoe UI', Arial, sans-serif;
    background: var(--deriv-light);
    color: var(--deriv-black);
    margin: 0;
    padding: 0;
  }
  .wrapper {
    max-width: 1200px;
    margin: 0 auto;
    padding: 32px 24px;
  }
  h1 {
    font-size: 32px;
    font-weight: 800;
    margin: 0 0 4px 0;
    color: var(--deriv-black);
    letter-spacing: -0.5px;
  }
  .sub {
    color: var(--deriv-gray);
    font-size: 14px;
    margin-bottom: 24px;
    padding-top: 8px;
    border-top: 1px solid var(--deriv-border);
  }
  .sub a {
    color: var(--deriv-red);
    text-decoration: none;
    font-weight: 500;
  }
  .sub a:hover { text-decoration: underline; }
  table {
    width: 100%;
    border-collapse: collapse;
    background: #fff;
    border-radius: 8px;
    overflow: hidden;
    box-shadow: 0 1px 3px rgba(0,0,0,.04);
    font-size: 14px;
  }
  th, td {
    padding: 12px 16px;
    text-align: left;
    border-bottom: 1px solid var(--deriv-border);
  }
  th {
    background: var(--deriv-light);
    color: var(--deriv-gray);
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #fafbfc; }
  .badge {
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    white-space: nowrap;
    display: inline-block;
  }
  .badge.trial      { background: #e3f2fd; color: var(--deriv-blue); }
  .badge.licenciado { background: #e8f5e9; color: var(--deriv-green); }
  .badge.expirado   { background: #fff3e0; color: #e65100; }
  .badge.revogado   { background: #eeeeee; color: #616161; }
  .badge.ativo      { background: #e8f5e9; color: var(--deriv-green); }
  .badge.pendente   { background: #fff8e1; color: #f57c00; }
  form { display: inline; }
  button {
    padding: 7px 14px;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
    margin-right: 4px;
    transition: all 0.15s ease;
  }
  .btn-extend { background: var(--deriv-green); color: #fff; }
  .btn-extend:hover { background: #3d9140; }
  .btn-revoke { background: var(--deriv-red); color: #fff; }
  .btn-revoke:hover { background: var(--deriv-red-dark); }
  .btn-reset { background: #6b6b6b; color: #fff; }
  .btn-reset:hover { background: #555; }
  .btn-new {
    background: var(--deriv-red);
    color: #fff;
    font-weight: 700;
    padding: 12px 24px;
    font-size: 14px;
  }
  .btn-new:hover { background: var(--deriv-red-dark); }
  .mono {
    font-family: 'IBM Plex Mono', Consolas, monospace;
    font-size: 12px;
    color: var(--deriv-gray);
    cursor: pointer;
    max-width: 180px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: inline-block;
    vertical-align: middle;
    padding: 2px 6px;
    background: var(--deriv-light);
    border-radius: 3px;
  }
  .mono:hover { color: var(--deriv-red); }
  .copied-msg {
    color: var(--deriv-green);
    font-size: 11px;
    font-weight: 700;
    margin-left: 6px;
    display: none;
  }
  .login-box {
    background: #fff;
    padding: 40px;
    border-radius: 8px;
    width: 400px;
    max-width: 9
