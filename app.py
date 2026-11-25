"""SecureDev Tickets - versión CORREGIDA (Evaluación Parcial 3, OCY1102).

Cambios de seguridad respecto de la versión base (ver informe, tabla de hallazgos):
  V1 SQL Injection en /search            -> consulta parametrizada
  V2 XSS almacenado en comentarios       -> se elimina "| safe" (autoescape) + CSP
  V3 Control de acceso roto (IDOR)       -> se valida que el ticket pertenezca al usuario
  V4 Búsqueda sin filtrar por dueño      -> WHERE owner_id = ?
  V5 Sin protección CSRF                 -> token CSRF por sesión en todos los POST
  V6 SECRET_KEY débil y por defecto      -> obligatoria por variable de entorno
  V7 Sin límite de intentos de login     -> bloqueo temporal + métricas
  V8 Sin cabeceras de seguridad          -> CSP, X-Frame-Options, nosniff, etc.
  V9 Cookie de sesión sin SameSite       -> HttpOnly + SameSite=Lax (+ Secure opcional)
  V10 Validación de entrada              -> límites de largo en comentarios y búsqueda
"""

import hmac
import os
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, abort, g, redirect, render_template, request, session, url_for
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from werkzeug.security import check_password_hash, generate_password_hash

HTTP_REQUESTS = Counter(
    "securedev_http_requests_total",
    "Solicitudes HTTP de la aplicación",
    ["endpoint", "method", "status"],
)
HTTP_DURATION = Histogram(
    "securedev_http_request_duration_seconds",
    "Duración de solicitudes HTTP",
    ["endpoint"],
)
LOGIN_FAILURES = Counter("securedev_login_failures_total", "Intentos de acceso fallidos")
LOGIN_BLOCKED = Counter(
    "securedev_login_blocked_total", "Intentos de acceso bloqueados por exceso de fallos"
)
ACCESS_DENIED = Counter(
    "securedev_access_denied_total", "Accesos denegados a recursos ajenos", ["endpoint"]
)
CSRF_REJECTED = Counter(
    "securedev_csrf_rejected_total", "Solicitudes POST rechazadas por token CSRF inválido"
)
# Se inicializan en 0 para que Prometheus pueda calcular increase() desde la primera vez.
for _endpoint in ("ticket", "add_comment"):
    ACCESS_DENIED.labels(_endpoint)

MAX_FAILED_LOGINS = 5
LOCK_WINDOW_SECONDS = 300
MAX_COMMENT_LENGTH = 1000
MAX_QUERY_LENGTH = 100
WEAK_KEYS = {"clave-insegura-solo-laboratorio", "changeme", "secret", ""}

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


def create_app(database_path=None, config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.getenv("SECRET_KEY"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
        PERMANENT_SESSION_LIFETIME=1800,
        MAX_CONTENT_LENGTH=16 * 1024,
        DATABASE_PATH=str(
            database_path or os.getenv("DATABASE_PATH", str(Path(__file__).with_name("securedev.db")))
        ),
    )
    if config:
        app.config.update(config)
    if app.config.get("SECRET_KEY") in WEAK_KEYS or len(app.config["SECRET_KEY"] or "") < 16:
        raise RuntimeError("Define una SECRET_KEY segura (>= 16 caracteres) en la variable de entorno.")
    app.logger.setLevel("INFO")

    failed_logins = defaultdict(deque)  # (ip, usuario) -> instantes de fallos recientes

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    # ---- CSRF ----
    def csrf_token():
        token = session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            session["csrf_token"] = token
        return token

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def before_request():
        g.request_started_at = time.perf_counter()
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("csrf_token", "").encode()
            expected = session.get("csrf_token", "").encode()
            if not expected or not hmac.compare_digest(sent, expected):
                CSRF_REJECTED.inc()
                app.logger.warning("CSRF_REJECTED ip=%s path=%s", request.remote_addr, request.path)
                abort(400)

    @app.after_request
    def after_request(response):
        if request.endpoint != "metrics":
            endpoint = request.endpoint or "unknown"
            HTTP_REQUESTS.labels(endpoint, request.method, str(response.status_code)).inc()
            started = g.get("request_started_at")
            if started is not None:
                HTTP_DURATION.labels(endpoint).observe(time.perf_counter() - started)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    with app.app_context():
        Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
        connection = db()
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY,
                owner_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY,
                ticket_id INTEGER NOT NULL,
                author_id INTEGER NOT NULL,
                body TEXT NOT NULL
            );
            """
        )
        if connection.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            connection.executemany(
                "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                [
                    (1, "ana", generate_password_hash("ana123")),
                    (2, "bruno", generate_password_hash("bruno123")),
                ],
            )
            connection.executemany(
                "INSERT INTO tickets (id, owner_id, title, body) VALUES (?, ?, ?, ?)",
                [
                    (1, 1, "Revisión de despliegue", "Preparar evidencias de CI/CD."),
                    (2, 2, "Acceso al panel", "Revisar registros de acceso."),
                ],
            )
        connection.commit()

    def current_user():
        return session.get("user_id")

    def owned_ticket_or_abort(ticket_id):
        item = db().execute(
            "SELECT id, owner_id, title, body FROM tickets WHERE id = ?", (ticket_id,)
        ).fetchone()
        if item is None:
            abort(404)
        if item["owner_id"] != current_user():
            ACCESS_DENIED.labels(request.endpoint).inc()
            app.logger.warning(
                "ACCESS_DENIED user_id=%s ticket_id=%s ip=%s", current_user(), ticket_id, request.remote_addr
            )
            abort(403)
        return item

    def lock_key(username):
        return (request.remote_addr or "?", username.lower())

    def is_locked(key):
        now = time.monotonic()
        attempts = failed_logins[key]
        while attempts and now - attempts[0] > LOCK_WINDOW_SECONDS:
            attempts.popleft()
        return len(attempts) >= MAX_FAILED_LOGINS

    @app.route("/")
    def index():
        if not current_user():
            return redirect(url_for("login"))
        tickets = db().execute(
            "SELECT id, title FROM tickets WHERE owner_id = ? ORDER BY id", (current_user(),)
        ).fetchall()
        return render_template("index.html", tickets=tickets)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        if request.method == "POST":
            username = request.form.get("username", "")[:64]
            password = request.form.get("password", "")[:128]
            key = lock_key(username)
            if is_locked(key):
                LOGIN_BLOCKED.inc()
                app.logger.warning("LOGIN_BLOCKED user=%s ip=%s", username, request.remote_addr)
                return render_template("login.html", error="Demasiados intentos fallidos. Intenta más tarde."), 429
            user = db().execute(
                "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                failed_logins.pop(key, None)
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                app.logger.info("LOGIN_OK user=%s ip=%s", username, request.remote_addr)
                return redirect(url_for("index"))
            failed_logins[key].append(time.monotonic())
            LOGIN_FAILURES.inc()
            app.logger.warning("LOGIN_FAILED user=%s ip=%s", username, request.remote_addr)
            error = "Credenciales inválidas"
        return render_template("login.html", error=error)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.get("/tickets/<int:ticket_id>")
    def ticket(ticket_id):
        if not current_user():
            return redirect(url_for("login"))
        item = owned_ticket_or_abort(ticket_id)
        comments = db().execute(
            "SELECT body FROM comments WHERE ticket_id = ? ORDER BY id", (ticket_id,)
        ).fetchall()
        return render_template("ticket.html", ticket=item, comments=comments)

    @app.post("/tickets/<int:ticket_id>/comments")
    def add_comment(ticket_id):
        if not current_user():
            return redirect(url_for("login"))
        owned_ticket_or_abort(ticket_id)
        body = request.form.get("body", "").strip()
        if not body or len(body) > MAX_COMMENT_LENGTH:
            abort(400)
        db().execute(
            "INSERT INTO comments (ticket_id, author_id, body) VALUES (?, ?, ?)",
            (ticket_id, current_user(), body),
        )
        db().commit()
        return redirect(url_for("ticket", ticket_id=ticket_id))

    @app.get("/search")
    def search():
        if not current_user():
            return redirect(url_for("login"))
        query = request.args.get("q", "")[:MAX_QUERY_LENGTH]
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        tickets = db().execute(
            "SELECT id, title FROM tickets WHERE owner_id = ? AND title LIKE ? ESCAPE '\\' ORDER BY id",
            (current_user(), f"%{escaped}%"),
        ).fetchall()
        return render_template("search.html", tickets=tickets, query=query)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/metrics")
    def metrics():
        return app.response_class(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

    return app


if __name__ == "__main__":
    # Solo desarrollo local. En el contenedor se usa gunicorn (ver Dockerfile).
    create_app().run(host="127.0.0.1", port=8000, debug=False)
