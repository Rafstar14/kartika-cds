#!/usr/bin/env bash
# Usage: sudo bash scripts/run_netns.sh start|stop
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
RUN="$PWD/run"; mkdir -p "$RUN" data/low data/high
case "${1:-}" in
  start)
    [ "$(id -u)" = 0 ] || { echo "Jalankan sebagai root (sudo)."; exit 1; }
    bash scripts/gen_key.sh >/dev/null
    if [ -z "${DIODE_REQUIRE_ENGINES:-}" ]; then
      if python3 -c "import sys; from low_side.gate_inspector import ClamEngine; sys.exit(0 if ClamEngine().available() else 1)" 2>/dev/null; then
        export DIODE_REQUIRE_ENGINES=yara,clamav
      else
        export DIODE_REQUIRE_ENGINES=yara
        echo "PERINGATAN: clamd tidak terjangkau. MODE TERBATAS (hanya YARA); UI akan menampilkannya."
      fi
    fi
    ip netns exec diode-high env PYTHONDONTWRITEBYTECODE=1 DIODE_RX_BIND=10.10.10.3 python3 -m high_side.udp_receiver >"$RUN/receiver.log" 2>&1 & echo $! >"$RUN/receiver.pid"
    ip netns exec diode-high env PYTHONDONTWRITEBYTECODE=1 HIGH_UI_HOST=10.10.10.3 HIGH_UI_PORT=5001 python3 -m high_side.app >"$RUN/high_ui.log" 2>&1 & echo $! >"$RUN/high_ui.pid"
    ip netns exec diode-low  env PYTHONDONTWRITEBYTECODE=1 LOW_UI_HOST=10.10.10.2 LOW_UI_PORT=5000 DIODE_RX_HOST=10.10.10.3 python3 -m low_side.app >"$RUN/low_ui.log" 2>&1 & echo $! >"$RUN/low_ui.pid"
    sleep 1
    echo "Sisi luar : http://10.10.10.2:5000"
    echo "Sisi dalam: http://10.10.10.3:5001"
    echo "Berdampingan: python3 -m http.server 8000 --bind 127.0.0.1 --directory demo  lalu buka http://127.0.0.1:8000/split.html"
    ;;
  stop)
    for f in "$RUN"/*.pid; do if [ -e "$f" ]; then kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; fi; done
    echo "Layanan dihentikan."
    ;;
  *) echo "Usage: $0 start|stop"; exit 1;;
esac
