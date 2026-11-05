#!/usr/bin/env bash
[ "$(id -u)" = 0 ] || { echo "Jalankan sebagai root (sudo)."; exit 1; }
cd "$(dirname "$0")/.."
bash scripts/run_netns.sh stop >/dev/null 2>&1 || true
nft delete table bridge diode 2>/dev/null || true
ip link del br-diode 2>/dev/null || true
ip link del vl-br 2>/dev/null || true
ip link del vh-br 2>/dev/null || true
ip netns del diode-low 2>/dev/null || true
ip netns del diode-high 2>/dev/null || true
echo "Topologi dibersihkan."
