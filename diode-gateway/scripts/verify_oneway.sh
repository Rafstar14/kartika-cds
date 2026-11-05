#!/usr/bin/env bash
# Bukti satu arah. Jalankan SETELAH setup_netns.sh dan SEBELUM run_netns.sh start
# (port 9999 harus bebas). Setiap baris harus LULUS.
cd "$(dirname "$0")/.."
[ "$(id -u)" = 0 ] || { echo "Jalankan sebagai root (sudo)."; exit 1; }
L="ip netns exec diode-low python3 scripts/_probe.py"; H="ip netns exec diode-high python3 scripts/_probe.py"
fails=0
check() { if [ "$2" = "$3" ]; then echo "  [LULUS] $1"; else echo "  [GAGAL] $1 (dapat: $2, harusnya: $3)"; fails=$((fails+1)); fi; }
echo "Arah yang HARUS jalan"
( $H listen-udp 9999 3 > /tmp/o1 ) & sleep 0.5; $L send-udp 10.10.10.3 9999; wait
check "luar -> dalam, UDP 9999" "$(cat /tmp/o1)" RECEIVED
echo "Yang HARUS diblokir (luar -> dalam selain 9999)"
( $H listen-udp 9998 2 > /tmp/o2 ) & sleep 0.5; $L send-udp 10.10.10.3 9998; wait
check "luar -> dalam, UDP 9998" "$(cat /tmp/o2)" NONE
( $H listen-tcp 5001 3 > /dev/null ) & sleep 0.5
check "luar -> dalam, TCP 5001" "$($L tcp-connect 10.10.10.3 5001 2)" BLOCKED; wait
echo "Jalur balik (dalam -> luar) HARUS mati"
( $L listen-udp 5555 2 > /tmp/o3 ) & sleep 0.5; $H send-udp 10.10.10.2 5555; wait
check "dalam -> luar, UDP" "$(cat /tmp/o3)" NONE
( $L listen-tcp 5000 3 > /dev/null ) & sleep 0.5
check "dalam -> luar, TCP 5000" "$($H tcp-connect 10.10.10.2 5000 2)" BLOCKED; wait
if ip netns exec diode-high ping -c1 -W1 10.10.10.2 >/dev/null 2>&1; then r=REPLY; else r=NOREPLY; fi
check "dalam -> luar, ping" $r NOREPLY
if ip netns exec diode-high arping -c1 -w1 -I vh 10.10.10.2 >/dev/null 2>&1; then r=REPLY; else r=NOREPLY; fi
check "dalam -> luar, ARP" $r NOREPLY
echo "Penghitung paket di firewall host:"
nft list chain bridge diode forward | sed 's/^/    /'
if [ "$fails" = 0 ]; then echo "SEMUA LULUS"; else echo "$fails pemeriksaan GAGAL"; exit 1; fi
