#!/usr/bin/env bash
# Pre-commit hook: gitleaks (secret detection) + bandit (Python static analysis)
set -e
export PATH="/opt/homebrew/bin:$PATH"

echo "[+] Running security pre-commit checks..."

# 1. Gitleaks check
if command -v gitleaks &> /dev/null; then
    echo " -> Running gitleaks..."
    gitleaks dir . --verbose
else
    echo " [!] Warning: gitleaks not installed. Skipping secret scanning."
fi

# 2. Bandit check
if command -v bandit &> /dev/null; then
    echo " -> Running bandit security scanner..."
    bandit -r app.py -ll
elif python3 -m bandit --version &> /dev/null; then
    echo " -> Running bandit via python3..."
    python3 -m bandit -r app.py -ll
else
    echo " [!] Warning: bandit not installed. Skipping static code security analysis."
fi

echo "[+] Pre-commit security checks passed successfully!"
