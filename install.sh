#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
if [ ! -f .env ]; then cp .env.example .env; fi
mkdir -p database
echo "Installation complete. Activate with: source .venv/bin/activate"
echo "Then start with: streamlit run app.py"
