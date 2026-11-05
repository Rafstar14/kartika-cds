import pytest
from common import protocol as P
from tests.helpers import KEY, ED_PRIV_KEY, ED_PUB_KEY


def test_roundtrip_hmac():
    pkt = P.pack(P.T_DATA, b"\x01" * 16, P.build_chunk(7, b"halo"), KEY)
    t, fid, body = P.unpack(pkt, KEY)
    assert (t, fid) == (P.T_DATA, b"\x01" * 16)
    assert P.parse_chunk(body) == (7, b"halo")


def test_roundtrip_ed25519():
    pkt = P.pack(P.T_DATA, b"\x02" * 16, P.build_chunk(3, b"radar-ot"), ED_PRIV_KEY)
    t, fid, body = P.unpack(pkt, ED_PUB_KEY)
    assert (t, fid) == (P.T_DATA, b"\x02" * 16)
    assert P.parse_chunk(body) == (3, b"radar-ot")


def test_ed25519_public_key_cannot_sign():
    with pytest.raises(P.ProtocolError):
        P.pack(P.T_DATA, b"\x02" * 16, P.build_chunk(0, b"x"), ED_PUB_KEY)


def test_tamper_and_wrong_key_rejected():
    pkt = bytearray(P.pack(P.T_DATA, b"\x01" * 16, P.build_chunk(0, b"abc"), KEY))
    pkt[30] ^= 1
    with pytest.raises(P.ProtocolError):
        P.unpack(bytes(pkt), KEY)
    good = P.pack(P.T_EOF, b"\x01" * 16, b"", KEY)
    with pytest.raises(P.ProtocolError):
        P.unpack(good, b"z" * 32)
    ed_pkt = bytearray(P.pack(P.T_DATA, b"\x01" * 16, P.build_chunk(0, b"abc"), ED_PRIV_KEY))
    ed_pkt[25] ^= 1
    with pytest.raises(P.ProtocolError):
        P.unpack(bytes(ed_pkt), ED_PUB_KEY)


def test_rs_4_2_recovers_any_two_missing_chunks():
    chunks = [bytes([i + 1]) * 64 for i in range(4)]
    p0, p1 = P.rs_encode_group(chunks)
    for m0 in range(4):
        for m1 in range(m0 + 1, 4):
            have = {i: chunks[i] for i in range(4) if i not in (m0, m1)}
            rec = P.rs_recover_group(4, 64, have, p0=p0, p1=p1)
            assert rec[m0] == chunks[m0] and rec[m1] == chunks[m1]


def test_garbage_and_oversize_rejected():
    for junk in (b"", b"x" * 10, b"x" * 2000, bytes(100)):
        with pytest.raises(P.ProtocolError):
            P.unpack(junk, KEY)


def test_header_name_length_mismatch():
    body = P.build_header(10, 1, 1024, 0, 4, bytes(32), "a.txt")
    with pytest.raises(P.ProtocolError):
        P.parse_header(body + b"extra")
