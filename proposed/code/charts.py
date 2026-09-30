"""Regenerate the Phase 4 comparison charts into ../../images/.

  fslake_comm_cost.png     communication cost (bits), paper Table 9 + BAKMM + FSL-AKE-IoD v2
  fslake_drone_cost.png    drone-side computation (ms, log scale), paper Table 8
  fslake_server_cost.png   server-side computation (ms), paper Table 8  (shows where FSL is NOT cheapest)
  fslake_hash_counts.png   instrumented hash operations per entity, BAKMM vs FSL v2 vs ablation M6-off

Run:  python charts.py
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import cost
import fslake as F

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "images")
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
OTHER, BASE, OURS = "#b9b8b2", "#6f6e69", "#2a78d6"      # compared schemes, BAKMM, proposal
SERIES = ["#2a78d6", "#eb6834"]                           # categorical slots 1-2 (DE, ES)


def _style(ax):
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.spines["bottom"].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=8, length=0)
    ax.yaxis.grid(True, color=GRID, lw=0.8)
    ax.set_axisbelow(True)


def _bars(rows, key, ylabel, fname, fmt, log=False, title=""):
    names = [r["scheme"] for r in rows]
    vals = [r[key] for r in rows]
    cols = [OURS if n.startswith("FSL") else BASE if n.startswith("BAKMM") else OTHER for n in names]
    fig, ax = plt.subplots(figsize=(8.4, 3.6))
    bars = ax.bar(names, vals, color=cols, width=0.62, edgecolor="white", linewidth=2)
    if log:
        ax.set_yscale("log")
    for b, v in zip(bars, vals):
        y = b.get_height()
        ax.annotate(fmt(v), (b.get_x() + b.get_width() / 2, y), xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8, color=INK)
    ax.set_ylabel(ylabel, color=MUTED, fontsize=9)
    ax.set_title(title, loc="left", fontsize=10, color=INK)
    _style(ax)
    plt.xticks(rotation=25, ha="right")
    plt.tight_layout()
    path = os.path.join(OUT, fname)
    plt.savefig(path, dpi=200)
    plt.close(fig)
    return path


def hash_counts(fname="fslake_hash_counts.png"):
    rows = [cost.count_bakmm(), cost.count_fsl(F.V2, "FSL-AKE-IoD v2"),
            cost.count_fsl(F.without(M6_two_message=False), "FSL v2 + MSG3 (M6 off)")]
    labels = [r["scheme"] for r in rows]
    fig, ax = plt.subplots(figsize=(7, 3.4))
    w, x = 0.36, range(len(rows))
    for k, (key, name) in enumerate((("de", "Drone (DE)"), ("es", "Ground station (ES)"))):
        vals = [r[key] for r in rows]
        bs = ax.bar([i + (k - 0.5) * w for i in x], vals, w, color=SERIES[k], label=name,
                    edgecolor="white", linewidth=2)
        for b, v in zip(bs, vals):
            ax.annotate(str(v), (b.get_x() + b.get_width() / 2, v), xytext=(0, 3), textcoords="offset points",
                        ha="center", fontsize=8, color=INK)
    ax.set_xticks(list(x), labels, fontsize=8)
    ax.set_ylabel("hash operations per session", color=MUTED, fontsize=9)
    ax.set_title("Instrumented hash count per entity", loc="left", fontsize=10, color=INK)
    ax.set_ylim(0, 10)
    ax.legend(frameon=False, fontsize=8, ncol=2, loc="upper right")
    _style(ax)
    plt.tight_layout()
    path = os.path.join(OUT, fname)
    plt.savefig(path, dpi=200)
    plt.close(fig)
    return path


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = cost.comparison_rows()
    out = [
        _bars(rows, "bits", "bits per authentication", "fslake_comm_cost.png", lambda v: f"{v}",
              title="Communication cost (paper Table 9 field sizes)"),
        _bars(rows, "drone_ms", "ms (log scale)", "fslake_drone_cost.png", lambda v: f"{v:g}", log=True,
              title="Drone-side computation (paper Table 7, T_h = 0.309 ms)"),
        _bars(rows, "server_ms", "ms (log scale)", "fslake_server_cost.png", lambda v: f"{v:g}", log=True,
              title="Server-side computation (paper Table 6, T_h = 0.055 ms)"),
        hash_counts(),
    ]
    return out


if __name__ == "__main__":
    for p in main():
        print("wrote", os.path.normpath(p))
