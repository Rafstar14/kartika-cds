import json
import random
import time
import pytest
from common import config, protocol as P
from common.audit import AuditLog, verify_chain
from high_side.udp_receiver import ReceiverCore
from low_side.udp_sender import build_plan
from tests.helpers import KEY, ED_PRIV_KEY, ED_PUB_KEY, make_pdf, make_png, make_firmware, rand_bytes, sha


@pytest.fixture
def core(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl")
    return ReceiverCore(KEY, tmp_path / "vault", tmp_path / "staging", audit, state_path=tmp_path / "live.json")


def plan_for(data, name="dokumen.pdf", key=KEY, **kw):
    return build_plan(data, b"\xaa" * 16, name, bytes.fromhex(sha(data)), key, **kw)


def feed(core, packets, loss=0.0, seed=0):
    rnd = random.Random(seed)
    for pkt in packets:
        if rnd.random() >= loss:
            core.handle(pkt)


def events(core):
    return [json.loads(l)["event"] for l in core.audit.path.read_text().splitlines()]


def test_clean_transfer_and_ed25519_transfer(tmp_path):
    audit = AuditLog(tmp_path / "audit_ed.jsonl")
    c_ed = ReceiverCore(ED_PUB_KEY, tmp_path / "vault_ed", tmp_path / "staging_ed", audit)
    data = make_firmware(3, 1)
    feed(c_ed, plan_for(data, name="radar_v31.bin", key=ED_PRIV_KEY))
    v = tmp_path / "vault_ed" / ("aa" * 16 + ".bin")
    assert v.read_bytes() == data
    ot = json.loads((tmp_path / "ot_radar_state.json").read_text())
    assert ot["firmware_version"] == "v3.1.0-KRTK-VERIFIED"


def test_fec_rs_4_2_recovers_two_losses_per_group_in_single_pass(core, tmp_path):
    data = make_pdf(rand_bytes(9000).replace(b"%%EOF", b"xxxxx"))
    plan = plan_for(data, passes=1)
    # Buang 2 paket DATA dari tiap grup (menguji kemampuan sejati RS(4,2) memulihkan 2 paket sekaligus!)
    drop, seen = set(), {}
    for i, pkt in enumerate(plan):
        t, _, body = P.unpack(pkt, KEY)
        if t == P.T_DATA:
            idx, _ = P.parse_chunk(body)
            g = idx // config.FEC_GROUP
            if seen.get(g, 0) < 2:
                seen[g] = seen.get(g, 0) + 1
                drop.add(i)
    feed(core, [p for i, p in enumerate(plan) if i not in drop])
    assert (tmp_path / "vault" / ("aa" * 16 + ".pdf")).read_bytes() == data
    meta = json.loads((tmp_path / "vault" / ("aa" * 16 + ".json")).read_text())
    assert meta["recovered_by_fec"] == len(drop) > 0


def test_forged_packets_are_dropped(core, tmp_path):
    data = make_pdf(b"x" * 3000)
    bad = plan_for(data)
    forged = []
    for p in bad:
        ptype, _, body = P.unpack(p, KEY)
        forged.append(P.pack(ptype, b"\xbb" * 16, body, b"z" * 32))
    feed(core, forged)
    assert core.stats["rejected_auth"] == len(forged)
    assert not core.active and not list((tmp_path / "vault").iterdir())


def test_path_traversal_name_cannot_escape_vault(core, tmp_path):
    data = make_png()
    plan = build_plan(data, b"\xee" * 16, "../../../../tmp/pwn.png", bytes.fromhex(sha(data)), KEY)
    feed(core, plan)
    stored = [p.name for p in (tmp_path / "vault").iterdir()]
    assert "ee" * 16 + ".png" in stored
    assert not (tmp_path.parent / "pwn.png").exists()
    meta = json.loads((tmp_path / "vault" / ("ee" * 16 + ".json")).read_text())
    assert meta["name"] == "pwn.png"


def test_high_side_revalidates_even_if_gate_was_bypassed(core, tmp_path):
    data = b"MZ" + bytes(500)
    feed(core, build_plan(data, b"\x22" * 16, "laporan.pdf", bytes.fromhex(sha(data)), KEY))
    assert "HIGH_REVALIDATION_FAILED" in events(core)
    assert not list((tmp_path / "vault").glob("*.pdf"))


def test_audit_chain_detects_edit(core, tmp_path):
    feed(core, plan_for(make_png(), name="g.png"))
    assert verify_chain(core.audit.path)["ok"]
    lines = core.audit.path.read_text().splitlines()
    lines[0] = lines[0].replace("TRANSFER_STARTED", "TRANSFER_STARTEX")
    core.audit.path.write_text("\n".join(lines) + "\n")
    assert not verify_chain(core.audit.path)["ok"]


def test_receiver_module_never_sends():
    import inspect, high_side.udp_receiver as m
    src = inspect.getsource(m)
    assert ".sendto(" not in src and ".send(" not in src and ".sendall(" not in src
