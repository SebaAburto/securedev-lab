"""Pruebas de seguridad automatizadas (se ejecutan en la etapa "Pruebas" de Jenkins).

Cada prueba demuestra que una vulnerabilidad está mitigada. Sobre la versión base
(vulnerable) estas pruebas FALLAN; sobre la versión corregida PASAN.
"""

import os
import re
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("SECRET_KEY", "clave-de-pruebas-solo-para-tests-0123456789")

import app as app_module  # noqa: E402

TOKEN_RE = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = app_module.create_app(database_path=os.path.join(self.tmp.name, "test.db"))
        self.app.config["TESTING"] = True

    def tearDown(self):
        self.tmp.cleanup()

    # ---------- utilidades ----------
    def client(self):
        return self.app.test_client()

    def token(self, client, path):
        html = client.get(path).get_data(as_text=True)
        match = TOKEN_RE.search(html)
        return match.group(1) if match else ""

    def login(self, user="ana", password="ana123"):
        client = self.client()
        resp = client.post(
            "/login",
            data={"username": user, "password": password, "csrf_token": self.token(client, "/login")},
        )
        self.assertEqual(resp.status_code, 302, "el login válido debe redirigir")
        return client

    # ---------- funcionamiento básico ----------
    def test_health_ok(self):
        self.assertEqual(self.client().get("/health").get_json(), {"status": "ok"})

    def test_login_invalido_muestra_error(self):
        client = self.client()
        resp = client.post(
            "/login",
            data={"username": "ana", "password": "mala", "csrf_token": self.token(client, "/login")},
        )
        self.assertIn("Credenciales inválidas", resp.get_data(as_text=True))

    def test_metrics_expone_contadores_de_seguridad(self):
        body = self.client().get("/metrics").get_data(as_text=True)
        self.assertIn("securedev_login_failures_total", body)

    # ---------- V1 SQL Injection ----------
    def test_v1_sql_injection_no_filtra_hashes(self):
        client = self.login()
        payload = "x' UNION SELECT id, username || ':' || password_hash FROM users --"
        body = client.get("/search", query_string={"q": payload}).get_data(as_text=True)
        self.assertNotIn("scrypt", body)
        self.assertNotIn("pbkdf2", body)
        self.assertNotIn("bruno:", body)

    # ---------- V4 búsqueda solo de tickets propios ----------
    def test_v4_busqueda_solo_tickets_propios(self):
        client = self.login()
        body = client.get("/search", query_string={"q": ""}).get_data(as_text=True)
        self.assertIn("Revisión de despliegue", body)
        self.assertNotIn("Acceso al panel", body)

    # ---------- V3 IDOR ----------
    def test_v3_no_se_puede_ver_ticket_ajeno(self):
        client = self.login()
        resp = client.get("/tickets/2")
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn("Revisar registros", resp.get_data(as_text=True))

    def test_v3_no_se_puede_comentar_ticket_ajeno(self):
        client = self.login()
        token = self.token(client, "/tickets/1")
        resp = client.post("/tickets/2/comments", data={"body": "intruso", "csrf_token": token})
        self.assertEqual(resp.status_code, 403)

    # ---------- V2 XSS almacenado ----------
    def test_v2_xss_almacenado_es_escapado(self):
        client = self.login()
        token = self.token(client, "/tickets/1")
        client.post(
            "/tickets/1/comments",
            data={"body": "<script>alert(1)</script>", "csrf_token": token},
        )
        body = client.get("/tickets/1").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)

    # ---------- V5 CSRF ----------
    def test_v5_comentario_sin_token_csrf_es_rechazado(self):
        client = self.login()
        resp = client.post("/tickets/1/comments", data={"body": "sin token"})
        self.assertEqual(resp.status_code, 400)

    def test_v5_login_sin_token_csrf_es_rechazado(self):
        resp = self.client().post("/login", data={"username": "ana", "password": "ana123"})
        self.assertEqual(resp.status_code, 400)

    # ---------- V6 SECRET_KEY ----------
    def test_v6_secret_key_obligatoria_y_no_debil(self):
        with mock.patch.dict(os.environ, {}):
            os.environ.pop("SECRET_KEY", None)
            with self.assertRaises(RuntimeError):
                app_module.create_app(database_path=os.path.join(self.tmp.name, "a.db"))
        with mock.patch.dict(os.environ, {"SECRET_KEY": "clave-insegura-solo-laboratorio"}):
            with self.assertRaises(RuntimeError):
                app_module.create_app(database_path=os.path.join(self.tmp.name, "b.db"))

    # ---------- V7 fuerza bruta ----------
    def test_v7_bloqueo_tras_intentos_fallidos(self):
        client = self.client()
        for _ in range(5):
            client.post(
                "/login",
                data={"username": "ana", "password": "mala", "csrf_token": self.token(client, "/login")},
            )
        resp = client.post(
            "/login",
            data={"username": "ana", "password": "ana123", "csrf_token": self.token(client, "/login")},
        )
        self.assertEqual(resp.status_code, 429)

    # ---------- V8 cabeceras ----------
    def test_v8_cabeceras_de_seguridad(self):
        headers = self.client().get("/login").headers
        for name in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"):
            self.assertIn(name, headers)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    # ---------- V9 cookie de sesión ----------
    def test_v9_cookie_de_sesion_httponly_y_samesite(self):
        cookie = self.client().get("/login").headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)

    # ---------- V10 validación de entrada ----------
    def test_v10_comentario_demasiado_largo_es_rechazado(self):
        client = self.login()
        token = self.token(client, "/tickets/1")
        resp = client.post("/tickets/1/comments", data={"body": "A" * 5000, "csrf_token": token})
        self.assertEqual(resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
