"""Simulasi keberhasilan transfer pada berbagai tingkat packet loss dengan Reed-Solomon RS(4, 2).
Jalankan: python3 scripts/loss_simulation.py   (tanpa jaringan, murni logika)"""
import hashlib
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common.audit import AuditLog                      # noqa: E402
from high_side.udp_receiver import ReceiverCore         # noqa: E402
from low_side.udp_sender import build_plan              # noqa: E402

KEY = b"k" * 32
TRIALS = 20
_counter = [0]


def trial(data, passes, loss, seed, tmp):
    plan = build_plan(data, b"\xaa" * 16, "uji.txt", hashlib.sha256(data).digest(), KEY, passes=passes)
    _counter[0] += 1
    d = Path(tmp) / f"t{_counter[0]}"
    core = ReceiverCore(KEY, d / "v", d / "s", AuditLog(d / "a.jsonl"))
    rnd = random.Random(seed)
    for pkt in plan:
        if rnd.random() >= loss:
            core.handle(pkt)
    for t in list(core.active.values()):
        if t.fd >= 0:
            import os
            os.close(t.fd)
            t.fd = -1
    return (d / "v" / ("aa" * 16 + ".txt")).exists()


def main():
    print(f"Persentase transfer yang selesai dengan Reed-Solomon RS(4,2) (tanpa ACK, {TRIALS} percobaan per sel)\n")
    with tempfile.TemporaryDirectory() as tmp:
        for label, size in (("60 KB", 60_000), ("250 KB", 250_000)):
            data = bytes(random.Random(1).choices(b"abcdefghij \n", k=size))
            print(f"Ukuran {label}")
            print("  loss   " + "".join(f"{p} pass".rjust(9) for p in (1, 2, 3, 4)))
            for loss in (0.05, 0.10, 0.20, 0.30):
                row = []
                for passes in (1, 2, 3, 4):
                    ok = sum(trial(data, passes, loss, s, tmp) for s in range(TRIALS))
                    row.append(f"{100 * ok // TRIALS}%".rjust(9))
                print(f"  {int(loss * 100):>3}%   " + "".join(row))
            print()


if __name__ == "__main__":
    main()
