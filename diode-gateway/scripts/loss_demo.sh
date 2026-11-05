#!/usr/bin/env bash
# Simulasi packet loss acak di jalur luar -> dalam memakai nftables (tanpa modul netem).
# Usage: sudo bash scripts/loss_demo.sh on [persen] | off | status
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "Jalankan sebagai root (sudo)."; exit 1; }
handle() { nft -a list chain bridge diode forward 2>/dev/null | grep "diode-loss-demo" | sed 's/.*# handle //' | head -1; }
case "${1:-}" in
  on)
    P="${2:-15}"
    h="$(handle)"; [ -n "$h" ] && nft delete rule bridge diode forward handle "$h"
    if nft insert rule bridge diode forward iifname vl-br numgen random mod 100 '<' "$P" counter drop comment diode-loss-demo; then
      echo "Loss acak ${P}% AKTIF di jalur luar -> dalam."
    else
      echo "GAGAL memasang aturan loss. Tidak ada loss yang disimulasikan."; exit 1
    fi ;;
  off)
    h="$(handle)"
    if [ -n "$h" ] && nft delete rule bridge diode forward handle "$h"; then echo "Loss dimatikan."; else echo "Tidak ada aturan loss yang aktif."; fi ;;
  status) nft list chain bridge diode forward ;;
  *) echo "Usage: $0 on [persen] | off | status"; exit 1 ;;
esac
