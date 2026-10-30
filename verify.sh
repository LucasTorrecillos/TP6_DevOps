#!/usr/bin/env bash
# Lance tous les contrôles de conformité du TP (depuis le dossier TP7-Secure Code)
set -u
pip install -q bandit pip-audit pytest -r app/requirements.txt 2>/dev/null

echo "== 1. Bandit (SAST) =="            ; bandit -r app -ll
echo "== 2. pip-audit (dépendances) =="  ; pip-audit -r app/requirements.txt --strict
echo "== 3. gitleaks (secrets) =="       ; gitleaks detect --source . --no-banner || echo "gitleaks non installé ou fuite détectée"
echo "== 4. Tests de conformité =="      ; pytest -q tests
