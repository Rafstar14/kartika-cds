"""Pengirim UDP satu arah (Simplex Transmitter). Tidak pernah memanggil recv: 0 ACK.

Keandalan tanpa jalur balik dengan dua lapis pertahanan:
 1. True Galois Field GF(2^8) Reed-Solomon Erasure Coding RS(4, 2):
    Setiap grup 4 chunk data menghasilkan 2 chunk paritas independen:
    - P0 (XOR Parity, index = g * 2)
    - P1 (GF(256) Vandermonde Parity, index = g * 2 + 1)
    Mampu memulihkan kehilangan 1 maupun 2 paket sekaligus dalam satu grup pada 1 pass!
 2. Multi-pass Interleaving (`passes` kali): pass genap dikirim dengan urutan grup terbalik
    agar burst packet loss tidak menghantam grup yang sama.
"""
import hashlib
import os
import socket
import time
from pathlib import Path
from typing import Union

from common import config, protocol as P


def build_plan(
    data: bytes,
    file_id: bytes,
    display_name: str,
    sha256: bytes,
    key: bytes,
    *,
    chunk_size=config.CHUNK_SIZE,
    fec_group=config.FEC_GROUP,
    passes=config.PASSES,
    ts=None,
):
    size = len(data)
    n = P.n_chunks(size, chunk_size)
    chunks = [data[i * chunk_size : (i + 1) * chunk_size] for i in range(n)]
    ts = int(time.time()) if ts is None else ts
    header = P.pack(
        P.T_HEADER,
        file_id,
        P.build_header(size, n, chunk_size, ts, fec_group, sha256, display_name),
        key,
    )
    eof = P.pack(P.T_EOF, file_id, b"", key)
    data_pkts = [P.pack(P.T_DATA, file_id, P.build_chunk(i, c), key) for i, c in enumerate(chunks)]
    ng = P.n_groups(n, fec_group) if fec_group else 0
    parity_pkts = []  # berisi pasangan (p0_pkt, p1_pkt) untuk tiap grup g
    for g in range(ng):
        padded = [P.pad(chunks[i], chunk_size) for i in P.group_range(g, n, fec_group)]
        p0, p1 = P.rs_encode_group(padded)
        # Paritas ke-0 (XOR) diberi index g*2, Paritas ke-1 (GF256) diberi index g*2 + 1
        p0_pkt = P.pack(P.T_PARITY, file_id, P.build_chunk(g * 2, p0), key)
        p1_pkt = P.pack(P.T_PARITY, file_id, P.build_chunk(g * 2 + 1, p1), key)
        parity_pkts.append((p0_pkt, p1_pkt))

    def one_pass(reverse):
        groups = range(ng - 1, -1, -1) if reverse else range(ng)
        if not fec_group:
            yield from (reversed(data_pkts) if reverse else data_pkts)
            return
        for g in groups:
            for i in P.group_range(g, n, fec_group):
                yield data_pkts[i]
            yield parity_pkts[g][0]
            yield parity_pkts[g][1]

    plan = [header] * 3
    for p in range(passes):
        if p:
            plan.append(header)
        plan.extend(one_pass(reverse=bool(p % 2)))
        plan.extend([eof] * 2)
    return plan


def send_file(
    source: Union[Path, str, bytes],
    display_name,
    sha256_hex,
    *,
    key,
    host=config.RX_HOST,
    port=config.RX_PORT,
    passes=config.PASSES,
    pace=config.PACE_S,
    chunk_size=config.CHUNK_SIZE,
    fec_group=config.FEC_GROUP,
    progress=None,
    sock=None,
    sleep=time.sleep,
):
    data = bytes(source) if isinstance(source, (bytes, bytearray)) else Path(source).read_bytes()
    if hashlib.sha256(data).hexdigest() != sha256_hex:
        raise ValueError("hash file berubah setelah pemeriksaan gate (TOCTOU); transfer dibatalkan")
    file_id = os.urandom(16)
    plan = build_plan(
        data,
        file_id,
        display_name,
        bytes.fromhex(sha256_hex),
        key,
        chunk_size=chunk_size,
        fec_group=fec_group,
        passes=passes,
    )
    own = sock is None
    sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        total = len(plan)
        for i, pkt in enumerate(plan, 1):
            sock.sendto(pkt, (host, port))
            if pace:
                sleep(pace)
            if progress and (i % 40 == 0 or i == total):
                progress(i, total)
    finally:
        if own:
            sock.close()
    return {"file_id": file_id.hex(), "packets": len(plan), "bytes": len(data)}
