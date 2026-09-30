"""Cost analysis: BAKMM-IoD vs proposed FSL-AKE-IoD.

1. Counts hash invocations per entity by instrumenting h(.) during real runs.
2. Measures wall-clock time of one full session on this machine (Python, SHA-256).
3. Converts counts to milliseconds with the SAME per-hash timings the BAKMM-IoD
   paper used (Table 8: 8Th = 2.47 ms on drone, 8Th = 0.44 ms on server), so the
   numbers are directly comparable with the paper's Table 8.
4. Computes communication cost with the paper's field sizes (Table 9).
5. Writes results.csv and two figures.
Run:  python3 benchmark.py
"""
import csv
import time
import common
from common import Clock, reset_hash_counter, hashes, size_bits
import bakmm_iod as B
import proposed_fslake as P

TH_DRONE = 2.47 / 8     # ms, from BAKMM-IoD Table 8
TH_SERVER = 0.44 / 8    # ms

# values reported in BAKMM-IoD Table 8 (drone ms, server ms) and Table 9 (msgs, bits)
LIT = {
    "Ali et al.":        (7.868, 0.394, 3, 3424),
    "Cho et al.":        (3100.125, 551.516, 3, 3968),
    "Rodrigues et al.":  (16.509, 1.843, 4, 3456),
    "Ever":              (74.583, 16.728, 6, 5344),
    "Bera et al.":       (7.405, 1.851, 3, 2368),
    "Mishra et al.":     (2.78, 0.39, 3, 1792),
    "Algarni and Jan":   (6.614, 0.33, 4, 2784),
}


def count_bakmm():
    clock = Clock(); _, es, de = B.setup(clock)
    reset_hash_counter(); m1 = de.start(); d = hashes()
    reset_hash_counter(); m2 = es.respond(m1); s = hashes()
    reset_hash_counter(); m3 = de.finish(m2); d += hashes()
    reset_hash_counter(); es.confirm(m3); s += hashes()
    # paper's cost model: M5 carries a 256-bit hash-masked value
    bits = size_bits(m1) + (size_bits(m2) - 160 + 256) + size_bits(m3)
    return d, s, 3, bits


def count_proposed():
    clock = Clock(); _, es, de = P.setup(clock)
    reset_hash_counter(); m1 = de.start(); d = hashes()
    reset_hash_counter(); m2, _ = es.respond(m1); s = hashes()
    reset_hash_counter(); de.finish(m2); d += hashes()
    return d, s, 2, size_bits(m1) + size_bits(m2)


def wallclock(mod, n=2000):
    clock = Clock(); _, es, de = mod.setup(clock)
    t0 = time.perf_counter()
    for _ in range(n):
        mod.run_session(de, es, clock); clock.advance(10)
    return (time.perf_counter() - t0) / n * 1000


if __name__ == "__main__":
    bd, bs, bm, bb = count_bakmm()
    pd, ps, pm, pb = count_proposed()
    rows = [("BAKMM-IoD", bd, bs, bd * TH_DRONE, bs * TH_SERVER, bm, bb),
            ("FSL-AKE-IoD (proposed)", pd, ps, pd * TH_DRONE, ps * TH_SERVER, pm, pb)]
    print(f"{'Scheme':26s}{'#h DE':>7s}{'#h ES':>7s}{'DE ms':>9s}{'ES ms':>9s}{'msgs':>6s}{'bits':>7s}")
    for r in rows:
        print(f"{r[0]:26s}{r[1]:7d}{r[2]:7d}{r[3]:9.3f}{r[4]:9.3f}{r[5]:6d}{r[6]:7d}")
    print(f"\nDrone computation saving : {100*(1-rows[1][3]/rows[0][3]):.1f} %")
    print(f"Server computation saving: {100*(1-rows[1][4]/rows[0][4]):.1f} %")
    print(f"Communication saving     : {100*(1-pb/bb):.1f} %  ({bb} -> {pb} bits, {bm} -> {pm} messages)")
    wb, wp = wallclock(B), wallclock(P)
    print(f"\nMeasured full-session time on this machine (Python/SHA-256): "
          f"BAKMM {wb:.4f} ms, proposed {wp:.4f} ms")

    with open("results.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scheme", "drone_ms", "server_ms", "messages", "bits"])
        for k, v in LIT.items():
            w.writerow([k, *v])
        for r in rows:
            w.writerow([r[0], round(r[3], 3), round(r[4], 3), r[5], r[6]])

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    names = list(LIT) + ["BAKMM-IoD", "Proposed"]
    bits = [v[3] for v in LIT.values()] + [bb, pb]
    drone = [v[0] for v in LIT.values()] + [rows[0][3], rows[1][3]]
    base, hi = "#9aa5b1", "#1f6feb"
    cols = [base] * len(LIT) + ["#6b7785", hi]

    fig, ax = plt.subplots(figsize=(8, 3.8))
    ax.bar(names, bits, color=cols)
    for i, v in enumerate(bits):
        ax.text(i, v + 60, str(v), ha="center", fontsize=8)
    ax.set_ylabel("Communication cost (bits)")
    ax.spines[["top", "right"]].set_visible(False)
    plt.xticks(rotation=30, ha="right", fontsize=8); plt.tight_layout()
    plt.savefig("fig_comm_cost.png", dpi=200)

    fig, ax = plt.subplots(figsize=(8, 3.8))
    ax.bar(names, drone, color=cols); ax.set_yscale("log")
    for i, v in enumerate(drone):
        ax.text(i, v * 1.15, f"{v:.2f}", ha="center", fontsize=8)
    ax.set_ylabel("Drone-side computation (ms, log scale)")
    ax.spines[["top", "right"]].set_visible(False)
    plt.xticks(rotation=30, ha="right", fontsize=8); plt.tight_layout()
    plt.savefig("fig_comp_cost.png", dpi=200)
    print("\nwrote results.csv, fig_comm_cost.png, fig_comp_cost.png")
