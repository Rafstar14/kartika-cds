#!/usr/bin/env bash
# Membangun topologi diode di satu mesin Linux (butuh root).
#
#   [diode-low 10.10.10.2] --vl--vl-br--[ br-diode 10.10.10.1 ]--vh-br--vh--[diode-high 10.10.10.3]
#
# Penegakan satu arah ada di HOST (nftables family bridge), BUKAN di dalam node dalam,
# jadi node dalam yang terkompromi tidak bisa menghapus aturannya sendiri.
# ARP statis dipasang di semua sisi supaya node dalam tidak perlu mengirim frame apa pun.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "Jalankan sebagai root (sudo)."; exit 1; }
NS_L=diode-low; NS_H=diode-high; BR=br-diode
ML=02:00:00:00:00:02; MH=02:00:00:00:00:03; MB=02:00:00:00:00:01
UI_L=${LOW_UI_PORT:-5000}; UI_H=${HIGH_UI_PORT:-5001}; PORT=${DIODE_RX_PORT:-9999}

bash "$(dirname "$0")/teardown_netns.sh" >/dev/null 2>&1 || true
ip netns add $NS_L; ip netns add $NS_H
ip link add vl type veth peer name vl-br
ip link add vh type veth peer name vh-br
ip link set vl address $ML; ip link set vh address $MH
ip link set vl netns $NS_L; ip link set vh netns $NS_H
ip link add $BR type bridge stp_state 0
ip link set $BR address $MB
ip link set vl-br master $BR; ip link set vh-br master $BR
ip addr add 10.10.10.1/24 dev $BR
ip link set $BR up; ip link set vl-br up; ip link set vh-br up

ip -n $NS_L addr add 10.10.10.2/24 dev vl; ip -n $NS_L link set lo up; ip -n $NS_L link set vl up
ip -n $NS_H addr add 10.10.10.3/24 dev vh; ip -n $NS_H link set lo up; ip -n $NS_H link set vh up
# ARP statis (tidak ada ARP request/reply yang perlu dilewatkan)
ip -n $NS_L neigh replace 10.10.10.3 lladdr $MH dev vl nud permanent
ip -n $NS_L neigh replace 10.10.10.1 lladdr $MB dev vl nud permanent
ip -n $NS_H neigh replace 10.10.10.1 lladdr $MB dev vh nud permanent
ip neigh replace 10.10.10.2 lladdr $ML dev $BR nud permanent
ip neigh replace 10.10.10.3 lladdr $MH dev $BR nud permanent
# matikan IPv6 dan forwarding L3 di bridge (supaya host tidak jadi jembatan balik)
for ns in $NS_L $NS_H; do
  ip netns exec $ns sysctl -qw net.ipv6.conf.all.disable_ipv6=1 2>/dev/null || echo "PERINGATAN: tidak bisa mematikan IPv6 di $ns"
done
sysctl -qw net.ipv6.conf.$BR.disable_ipv6=1 2>/dev/null || true
sysctl -qw net.ipv4.conf.$BR.forwarding=0 || echo "PERINGATAN: gagal mematikan forwarding IPv4 di $BR"

nft -f - <<NFT
table bridge diode {
  chain forward {
    type filter hook forward priority 0; policy drop;
    iifname "vl-br" ip saddr 10.10.10.2 ip daddr 10.10.10.3 udp dport $PORT counter accept
    iifname "vh-br" counter drop
  }
  chain input {
    type filter hook input priority 0; policy drop;
    iifname "vl-br" ip saddr 10.10.10.2 ip daddr 10.10.10.1 tcp sport $UI_L accept
    iifname "vh-br" ip saddr 10.10.10.3 ip daddr 10.10.10.1 tcp sport $UI_H accept
  }
}
NFT
echo "Topologi siap. Node luar 10.10.10.2, node dalam 10.10.10.3, host/operator 10.10.10.1."
