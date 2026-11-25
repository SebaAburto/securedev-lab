# SecureDev Tickets - versión corregida (EP3 OCY1102)

Contenido: app corregida (`app.py`, `templates/`, `static/`), `Dockerfile`, `compose.yaml` (app + Prometheus + Grafana),
`Jenkinsfile`, `tests/` (pruebas de seguridad), `ci/check_zap.py`, `monitoring/`, `jenkins/` y `.github/dependabot.yml`.

## Arranque rápido (PowerShell, en esta carpeta)
1. `Copy-Item .env.example .env` y edita los valores.
2. `docker compose up -d --build`
3. App: http://localhost:8000 | Prometheus: http://localhost:9090 | Grafana: http://localhost:3000

## Pruebas locales (sin Docker)
```
py -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt
$env:SECRET_KEY="una-clave-larga-de-pruebas-123456"
pytest -v
```

## Jenkins (carpeta `jenkins/`)
`cd jenkins ; docker compose up -d --build` -> http://localhost:8080
Detalle completo en la guía paso a paso.
