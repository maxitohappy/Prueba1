#!/usr/bin/env bash
# Ejecuta todos los análisis automáticos y guarda los informes en ./reportes
# Requisito: docker compose up -d   (las dos apps deben estar corriendo)
set -u
cd "$(dirname "$0")/.."
mkdir -p reportes && chmod 777 reportes   # ZAP escribe como otro usuario

echo "== 1/4 Bandit: busca fallas en el código Python =="
docker compose run --rm app-secure bandit -r app | tee reportes/bandit.txt

echo "== 2/4 pip-audit: busca dependencias con vulnerabilidades conocidas (CVE) =="
docker compose run --rm app-secure pip-audit -r requirements.txt | tee reportes/pip-audit.txt

echo "== 3/4 Gitleaks: busca claves y secretos en los archivos y el historial de git =="
docker run --rm -v "$PWD:/repo" zricethezav/gitleaks:latest git -v /repo \
  | tee reportes/gitleaks.txt

echo "== 4/4 OWASP ZAP (baseline, pasivo) contra ambas apps =="
for target in app-vuln app-secure; do
  docker compose run --rm zap zap-baseline.py -t "http://$target:5000" -r "zap-$target.html"
done

echo
echo "Listo. Abre reportes/zap-app-vuln.html y reportes/zap-app-secure.html y compáralos."
