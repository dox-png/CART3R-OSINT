import os
import ipaddress
import socket
import ssl
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-before-deploying")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
CSRFProtect(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

DB_PATH = os.environ.get("DATABASE_PATH", "osint.db")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS searches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


def normalize_domain(value):
    raw = (value or "").strip()
    if not raw or len(raw) > 253 or any(ch in raw for ch in "/?#@"):
        raise ValueError("Entre un nom de domaine, par exemple example.com.")
    parsed = urlparse("//" + raw)
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host or "." not in host:
        raise ValueError("Le nom de domaine semble invalide.")
    try:
        host.encode("idna")
    except UnicodeError:
        raise ValueError("Nom de domaine invalide.")
    if len(host) > 253 or any(not part or len(part) > 63 for part in host.split(".")):
        raise ValueError("Nom de domaine invalide.")
    return host


def resolve_public_addresses(host):
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("Impossible de résoudre ce domaine.")
    addresses = sorted({item[4][0] for item in records})
    if not addresses:
        raise ValueError("Aucune adresse IP trouvée.")
    # Reject the whole result if any answer is not globally routable.
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("Pour des raisons de sécurité, seules les adresses IP publiques sont acceptées.")
    return addresses


def inspect_tls(host, addresses):
    context = ssl.create_default_context()
    last_error = None
    for address in addresses:
        try:
            # Connect to the already-validated IP, while preserving TLS hostname verification.
            with socket.create_connection((address, 443), timeout=4) as raw:
                with context.wrap_socket(raw, server_hostname=host) as secure:
                    cert = secure.getpeercert()
                    return {
                        "version": secure.version() or "Inconnue",
                        "expires": cert.get("notAfter", "Non communiqué"),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "Non communiqué")
                    }
        except (OSError, ssl.SSLError) as exc:
            last_error = str(exc)
    return {"error": "Vérification TLS indisponible pour ce domaine."}


def analyze_domain(value):
    host = normalize_domain(value)
    addresses = resolve_public_addresses(host)
    tls = inspect_tls(host, addresses)
    return {"domain": host, "addresses": addresses, "tls": tls}


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; manifest-src 'self'; connect-src 'self'; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
    )
    return response


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        try:
            result = analyze_domain(request.form.get("domain", ""))
            with db() as conn:
                conn.execute(
                    "INSERT INTO searches(domain, created_at) VALUES (?, ?)",
                    (result["domain"], datetime.now(timezone.utc).isoformat())
                )
            flash("Analyse terminée.", "success")
        except ValueError as exc:
            flash(str(exc), "error")
    with db() as conn:
        history = conn.execute(
            "SELECT domain, created_at FROM searches ORDER BY id DESC LIMIT 8"
        ).fetchall()
    return render_template("index.html", result=result, history=history)


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/manifest.webmanifest")
def manifest():
    return app.send_static_file("manifest.webmanifest")


@app.route("/service-worker.js")
def service_worker():
    response = app.send_static_file("service-worker.js")
    response.headers["Service-Worker-Allowed"] = "/"
    return response


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
