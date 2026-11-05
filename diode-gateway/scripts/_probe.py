"""Alat bantu untuk verify_oneway.sh. Mode:
  listen-udp PORT DETIK   -> cetak RECEIVED atau NONE
  send-udp IP PORT        -> kirim satu datagram
  listen-tcp PORT DETIK   -> terima satu koneksi; cetak CONNECTED atau NONE
  tcp-connect IP PORT DET -> cetak CONNECTED atau BLOCKED"""
import socket
import sys

mode = sys.argv[1]
if mode == "listen-udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", int(sys.argv[2])))
    s.settimeout(float(sys.argv[3]))
    try:
        s.recvfrom(100)
        print("RECEIVED")
    except socket.timeout:
        print("NONE")
elif mode == "send-udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"probe", (sys.argv[2], int(sys.argv[3])))
elif mode == "listen-tcp":
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", int(sys.argv[2])))
    s.listen(1)
    s.settimeout(float(sys.argv[3]))
    try:
        s.accept()
        print("CONNECTED")
    except socket.timeout:
        print("NONE")
elif mode == "tcp-connect":
    try:
        socket.create_connection((sys.argv[2], int(sys.argv[3])), timeout=float(sys.argv[4])).close()
        print("CONNECTED")
    except OSError:
        print("BLOCKED")
