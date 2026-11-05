#!/usr/bin/env bash
# Mode pengembangan: semua di localhost, TANPA isolasi jaringan.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
bash scripts/gen_key.sh >/dev/null
mkdir -p run data/low data/high

export DIODE_RX_HOST=127.0.0.1 DIODE_RX_BIND=127.0.0.1
export LOW_UI_HOST=127.0.0.1 LOW_UI_PORT=5000 HIGH_UI_HOST=127.0.0.1 HIGH_UI_PORT=5001

if [ -z "${DIODE_REQUIRE_ENGINES:-}" ]; then
  if python3 -c "import sys; from low_side.gate_inspector import ClamEngine; sys.exit(0 if ClamEngine().available() else 1)" 2>/dev/null; then
    export DIODE_REQUIRE_ENGINES=yara,clamav
  else
    export DIODE_REQUIRE_ENGINES=yara
    echo "PERINGATAN: clamd tidak terjangkau. Jalan dalam MODE TERBATAS (hanya YARA)."
  fi
fi

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM
python3 -m high_side.udp_receiver & pids+=($!)
python3 -m high_side.app & pids+=($!)
python3 -m low_side.app & pids+=($!)
sleep 1
echo
echo "Sisi luar : http://127.0.0.1:5000"
echo "Sisi dalam: http://127.0.0.1:5001"
echo "Tampilan berdampingan: python3 -m http.server 8000 --bind 127.0.0.1 --directory demo  lalu buka http://127.0.0.1:8000/split.html?mode=dev"
echo "Tekan Ctrl+C untuk berhenti."
wait
