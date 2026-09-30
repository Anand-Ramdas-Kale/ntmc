"""Phase 4: cost verification.

  * hash operations per entity, counted by instrumenting h() during real runs (not by hand)
  * communication cost with the paper's field sizes (ID/nonce 160, hash 256, timestamp 32)
  * real SHA-256 timing on this machine (10^5 runs) and full-session timing
  * cost under the paper's Table 6/7 per-hash times, and the Table 8/9 comparison
  * birthday bound for 160-bit TID collisions

Run:  python cost.py
"""
import hashlib
import math
import os
import statistics
import time

import bakmm_iod as B
import bakmm_literal as L
import fslake as F
import proposed_fslake as P1
from common import Clock, h, hashes, reset_hash_counter, size_bits

TH_SERVER = 0.055     # ms, paper Table 6 (average T_h, server)
TH_DRONE = 0.309      # ms, paper Table 7 (average T_h, Raspberry Pi 3)

# Paper Table 8 (drone ms, server ms, drone formula, server formula) and Table 9 (messages, bits)
LIT = {
    "Ali et al.":       (7.868, 0.394, "18Th+Tfe+Tsenc", "7Th+3Tsenc/Tsdec", 3, 3424),
    "Cho et al.":       (3100.125, 551.516, "2Tecsigv+Tsdec+10001Th", "2Tecsigg+Tsenc+10001Th", 3, 3968),
    "Rodrigues et al.": (16.509, 1.843, "9Th+6Tecm", "9Th+2Tecm", 4, 3456),
    "Ever":             (74.583, 16.728, "9Th+2Tbp+2Tmtp+3Tecm", "6Th+3Tbp+2Tmtp+3Tecm", 6, 5344),
    "Bera et al.":      (7.405, 1.851, "9Th+2Tsenc/Tsdec+2Tecm+Teca", "9Th+2Tsenc/Tsdec+2Tecm+Teca", 3, 2368),
    "Mishra et al.":    (2.78, 0.39, "9Th", "7Th", 3, 1792),
    "Algarni and Jan":  (6.614, 0.33, "Tfe+14Th", "6Th", 4, 2784),
}
PAPER_BAKMM = (2.47, 0.44, "8Th", "8Th", 3, 1792)


# --------------------------------------------------------------------------- instrumentation
def _count(fn, *a):
    reset_hash_counter()
    out = fn(*a)
    return out, hashes()


def count_bakmm(policy="on_confirm"):
    c = Clock(); _, es, de = B.setup(c, policy)
    m1, d1 = _count(de.start); c.advance()
    m2, s1 = _count(es.respond, m1); c.advance()
    m3, d2 = _count(de.finish, m2); c.advance()
    _, s2 = _count(es.confirm, m3)
    actual = size_bits(m1) + size_bits(m2) + size_bits(m3)
    paper = actual - 160 + 256                    # the paper counts M5 as a 256-bit value
    return dict(scheme="BAKMM-IoD", de=d1 + d2, es=s1 + s2, msgs=3, bits=paper, bits_actual=actual,
                per_msg=[size_bits(m1), size_bits(m2) - 160 + 256, size_bits(m3)],
                de_steps=dict(AKDDE1=d1, AKDDE3=d2), es_steps=dict(AKDDE2=s1, AKDDE4=s2))


def count_fsl(cfg=F.V2, label="FSL-AKE-IoD v2"):
    c = Clock(); _, es, de = F.setup(c, cfg)
    # one warm-up session so the retry-pseudonym precomputation is in steady state
    F.run_session(de, es, c); c.advance(10)
    m1, d1 = _count(de.start); c.advance()
    (m2, _), s1 = _count(es.respond, m1); c.advance()
    out, d2 = _count(de.finish, m2)
    msgs, bits, s2 = 2, size_bits(m1) + size_bits(m2), 0
    per = [size_bits(m1), size_bits(m2)]
    if not cfg.M6_two_message:
        _, m3 = out; c.advance()
        _, s2 = _count(es.confirm, m3)
        msgs, bits = 3, bits + size_bits(m3)
        per.append(size_bits(m3))
    return dict(scheme=label, de=d1 + d2, es=s1 + s2, msgs=msgs, bits=bits, bits_actual=bits, per_msg=per,
                de_steps=dict(start=d1, finish=d2), es_steps=dict(respond=s1, confirm=s2))


def count_fsl_v1():
    c = Clock(); _, es, de = P1.setup(c)
    m1, d1 = _count(de.start); c.advance()
    (m2, _), s1 = _count(es.respond, m1); c.advance()
    _, d2 = _count(de.finish, m2)
    return dict(scheme="FSL-AKE-IoD v1 (draft)", de=d1 + d2, es=s1, msgs=2,
                bits=size_bits(m1) + size_bits(m2), per_msg=[size_bits(m1), size_bits(m2)])


def count_bakmm_km():
    """ES<->CS key management (corrected reading): ES = initiator, CS = responder."""
    c = Clock(); e, cs = L.RAKM.register(c)
    es, csr = L.ESInitiator(e, c), L.CSResponder(cs, c)
    m1, a = _count(es.akdec1); c.advance()
    m2, b = _count(csr.akdec2, m1); c.advance()
    m3, a2 = _count(es.akdec3, m2); c.advance()
    _, b2 = _count(csr.akdec4, m3)
    return dict(scheme="BAKMM-IoD ES-CS (corrected)", es=a + a2, cs=b + b2,
                bits=size_bits(m1) + size_bits(m2) - 160 + 256 + size_bits(m3), msgs=3)


# --------------------------------------------------------------------------- timing
def sha256_timing(runs=100_000):
    """Per-call timing of h() (5-part input, SHA-256) and of raw hashlib.sha256 on 64 bytes."""
    parts = (os.urandom(32), os.urandom(20), os.urandom(20), 1_700_000_000, 1_700_000_001)
    raw = os.urandom(64)
    pc = time.perf_counter_ns
    th, tr = [], []
    for _ in range(runs):
        t0 = pc(); h(*parts); th.append(pc() - t0)
    for _ in range(runs):
        t0 = pc(); hashlib.sha256(raw).digest(); tr.append(pc() - t0)
    ms = lambda v: v / 1e6
    return dict(runs=runs,
                h_mean_ms=ms(statistics.fmean(th)), h_std_ms=ms(statistics.pstdev(th)),
                h_median_ms=ms(statistics.median(th)),
                raw_mean_ms=ms(statistics.fmean(tr)), raw_std_ms=ms(statistics.pstdev(tr)),
                raw_median_ms=ms(statistics.median(tr)))


def session_timing(n=5000):
    res = {}
    for name, mod, cfg in (("BAKMM-IoD", B, None), ("FSL-AKE-IoD v2", F, F.V2)):
        c = Clock()
        _, es, de = (mod.setup(c) if cfg is None else mod.setup(c, cfg))
        ts = []
        for _ in range(n):
            t0 = time.perf_counter_ns(); mod.run_session(de, es, c); ts.append(time.perf_counter_ns() - t0)
            c.advance(10)
        res[name] = dict(mean_ms=statistics.fmean(ts) / 1e6, std_ms=statistics.pstdev(ts) / 1e6,
                         median_ms=statistics.median(ts) / 1e6)
    return res


# --------------------------------------------------------------------------- comparison
def comparison_rows():
    b, f = count_bakmm(), count_fsl()
    rows = [dict(scheme=k, drone_ms=v[0], server_ms=v[1], drone_f=v[2], server_f=v[3], msgs=v[4], bits=v[5])
            for k, v in LIT.items()]
    rows.append(dict(scheme="BAKMM-IoD", drone_ms=round(b["de"] * TH_DRONE, 3), server_ms=round(b["es"] * TH_SERVER, 3),
                     drone_f=f"{b['de']}Th", server_f=f"{b['es']}Th", msgs=b["msgs"], bits=b["bits"]))
    rows.append(dict(scheme="FSL-AKE-IoD (v2)", drone_ms=round(f["de"] * TH_DRONE, 3), server_ms=round(f["es"] * TH_SERVER, 3),
                     drone_f=f"{f['de']}Th", server_f=f"{f['es']}Th", msgs=f["msgs"], bits=f["bits"]))
    return rows


def strictly_cheaper(rows):
    """For the proposal: every scheme that beats or ties it on each metric."""
    me = next(r for r in rows if r["scheme"].startswith("FSL"))
    out = {}
    for metric in ("drone_ms", "server_ms", "bits", "msgs"):
        out[metric] = [(r["scheme"], r[metric]) for r in rows
                       if r is not me and r[metric] <= me[metric] + 1e-9]
    return me, out


def tid_collision_bound(n_bits=160, drones=10**6, sessions=10**6):
    """Birthday bound: P(any two of G pseudonyms collide) <= G^2 / 2^(n+1)."""
    G = drones * sessions * 2        # at most 2 live records per session (anchor + one candidate)
    p = G * G / 2 ** (n_bits + 1)
    return dict(n_bits=n_bits, pseudonyms=G, bound=p, log10=math.log10(p))


if __name__ == "__main__":
    b, v1, f = count_bakmm(), count_fsl_v1(), count_fsl()
    b2 = count_bakmm("on_send")
    for r in (b, b2, v1, f):
        print(f"{r['scheme']:28s} DE {r['de']}  ES {r['es']}  msgs {r['msgs']}  bits {r['bits']}  per-msg {r['per_msg']}")
    print("BAKMM steps:", b["de_steps"], b["es_steps"])
    print("ES-CS (BAKMM corrected):", count_bakmm_km())
    for label, cfg in (("M6 off (3 msgs)", F.without(M6_two_message=False)),
                       ("M5 off (plain K)", F.without(M5_masked_verifier=False)),
                       ("retry pseudonyms w=3", F.without(retry_pseudonyms=3))):
        r = count_fsl(cfg, label)
        print(f"{label:28s} DE {r['de']}  ES {r['es']}  msgs {r['msgs']}  bits {r['bits']}")
    t = sha256_timing()
    print(f"\nSHA-256 via h(): mean {t['h_mean_ms']*1000:.3f} us  std {t['h_std_ms']*1000:.3f} us  "
          f"(raw hashlib 64 B: {t['raw_mean_ms']*1000:.3f} +- {t['raw_std_ms']*1000:.3f} us), n={t['runs']}")
    for k, v in session_timing().items():
        print(f"full session {k:16s} mean {v['mean_ms']*1000:.1f} us  std {v['std_ms']*1000:.1f} us")
    print("\nPaper T_h: drone", TH_DRONE, "ms, server", TH_SERVER, "ms")
    rows = comparison_rows()
    for r in rows:
        print(f"  {r['scheme']:20s} {r['drone_f']:>28s} {r['drone_ms']:>9.3f}  {r['server_f']:>28s} {r['server_ms']:>8.3f}  {r['msgs']}  {r['bits']}")
    me, ties = strictly_cheaper(rows)
    print("schemes at least as cheap as FSL-AKE-IoD:", ties)
    print("160-bit TID collision bound:", tid_collision_bound())
