"""Falla el pipeline si OWASP ZAP reporta alertas de riesgo ALTO. Resume el resto."""
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "reports/zap-report.json"
with open(path, encoding="utf-8") as fh:
    report = json.load(fh)

names = {"3": "ALTO", "2": "MEDIO", "1": "BAJO", "0": "INFO"}
counts = {k: 0 for k in names}
for site in report.get("site", []):
    for alert in site.get("alerts", []):
        counts[alert.get("riskcode", "0")] += 1
        print(f"[{names.get(alert.get('riskcode', '0'))}] {alert.get('name')}")

print("Resumen ZAP:", {names[k]: v for k, v in counts.items()})
if counts["3"]:
    print("Quality gate: hay alertas de riesgo ALTO -> pipeline FALLA")
    sys.exit(1)
print("Quality gate: sin alertas de riesgo ALTO")
