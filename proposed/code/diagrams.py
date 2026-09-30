"""Draw fslake_auth.svg (message flow) and fslake_architecture.svg into the repository root.
Graphviz is not installed on the authoring machine, so these SVGs are drawn with matplotlib from the
same content as fslake_auth.dot / fslake_architecture.dot.  Run:  python diagrams.py
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
INK, MUTED = "#0b0b0b", "#52514e"
C1, C2 = "#2a78d6", "#eb6834"


def _box(ax, x, y, w, hh, text, fc, fs=8.2, title=None):
    ax.add_patch(FancyBboxPatch((x, y), w, hh, boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc=fc, ec="#8c8b86", lw=0.9))
    if title:
        ax.text(x + w / 2, y + hh - 0.12, title, ha="center", va="top", fontsize=9.5, weight="bold", color=INK)
        ax.text(x + w / 2, y + hh - 0.42, text, ha="center", va="top", fontsize=fs, color=INK, linespacing=1.4)
    else:
        ax.text(x + w / 2, y + hh / 2, text, ha="center", va="center", fontsize=fs, color=INK, linespacing=1.4)


def _arrow(ax, x1, y1, x2, y2, label, color, dy=0.1, ls="-"):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", lw=1.4, color=color, ls=ls))
    if label:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + dy, label, ha="center", va="bottom", fontsize=8.6, color=color)


def auth_flow(path):
    fig, ax = plt.subplots(figsize=(11, 7.4))
    ax.set_xlim(0, 11); ax.set_ylim(0, 7.4); ax.axis("off")
    _box(ax, 0.3, 6.5, 3.2, 0.75, "stores {TID, K}", "#e8f1ff", title="Drone DE_i")
    _box(ax, 7.3, 6.5, 3.4, 0.75, "SE: X_ES   DB: C = K xor h(X_ES||TID)", "#fff4e0", title="Ground station ES_j")
    for x in (1.9, 9.0):
        ax.plot([x, x], [0.2, 6.5], ls="--", lw=0.8, color="#c8c7c1")
    _box(ax, 0.3, 5.05, 3.2, 1.15, "pick N1, T1\nV1 = h(K||TID||N1||T1)\nretry only after > 2dT  (F4)", "#f6f8fa")
    _arrow(ax, 3.5, 4.75, 7.3, 4.75, "MSG1 = {TID, N1, T1, V1}    608 bits", C1)
    _box(ax, 6.0, 2.35, 4.7, 2.15,
         "|T1 - T*| <= dT ;  (TID,T1,N1) not in cache\n(cache entry kept until T1 + dT  - F2)\n"
         "K = C xor h(X_ES||TID) ;  check V1\npick N2, T2\nSK = h(K||N1||N2||T1||T2||TID) ;  V2 = h(SK||N2||T2)\n"
         "matched anchor -> add candidate (TID', K')\nmatched candidate -> promote it  (F3)", "#f6f8fa", fs=8)
    _arrow(ax, 6.0, 2.05, 3.5, 2.05, "MSG2 = {N2, T2, V2}    448 bits", C2)
    _box(ax, 0.3, 0.35, 3.9, 1.4,
         "|T2 - T*| <= dT ;  recompute SK ;  check V2\nK <- h(K||SK)\nTID <- h(TID||SK)[:160]\nerase N1 and the old K",
         "#f6f8fa", fs=8)
    ax.text(5.5, 0.55, "MSG2 lost -> drone still holds (TID, K) = anchor at ES;\nnext run succeeds and promotes a fresh candidate",
            ha="left", fontsize=8, color=MUTED, style="italic")
    plt.tight_layout(); plt.savefig(path, format="svg"); plt.close(fig)


def architecture(path):
    fig, ax = plt.subplots(figsize=(11.5, 5.8))
    ax.set_xlim(0, 11.5); ax.set_ylim(0, 5.8); ax.axis("off")
    _box(ax, 3.6, 4.45, 4.3, 1.15, "issues {TID_i, K_i}; masked C_i to ES\nadds / revokes drones; must erase K_i",
         "#f3e8ff", title="Registration Authority (offline)")
    _box(ax, 0.2, 0.6, 2.8, 3.2, "{TID_i, K_i}\n\n5 hash / session\n\nafter each session\nK <- h(K||SK)\nTID <- h(TID||SK)",
         "#e8f1ff", title="Drones DE_i")
    _box(ax, 4.2, 0.6, 3.1, 3.2, "secure element: X_ES\nDB: anchor + candidates\n(masked C)\nreplay cache until T1+dT\n\n7 hash / session\npartial blocks (ECC, ECDSA)",
         "#fff4e0", title="Ground station ES_j")
    _box(ax, 8.5, 0.6, 2.8, 3.2, "P2P network, pBFT\nverify ECDSA\nappend block\n\nES<->CS keys:\nsame 2-message AKE\n(ES = initiator)",
         "#e9f7ef", title="Cloud servers CS_k")
    _arrow(ax, 3.05, 2.6, 4.15, 2.6, "MSG1", C1)
    _arrow(ax, 4.15, 1.9, 3.05, 1.9, "MSG2", C2)
    _arrow(ax, 7.35, 2.6, 8.45, 2.6, "FSL-AKE", C1)
    _arrow(ax, 8.45, 1.9, 7.35, 1.9, "", C2)
    _arrow(ax, 7.35, 1.2, 8.45, 1.2, "E_SK(blocks)", MUTED)
    for x2 in (1.6, 5.75, 9.9):
        _arrow(ax, 5.75, 4.4, x2, 3.85, "", "#8c8b86", ls="--")
    ax.text(5.75, 0.15, "Open channel: Dolev-Yao + CK adversary (eavesdrop, modify, drop, replay; capture drones; read ES DB but not the SE)",
            ha="center", fontsize=8.2, color="#9a2b2b")
    plt.tight_layout(); plt.savefig(path, format="svg"); plt.close(fig)


if __name__ == "__main__":
    a, b = os.path.join(ROOT, "fslake_auth.svg"), os.path.join(ROOT, "fslake_architecture.svg")
    auth_flow(a); architecture(b)
    for p in (a, b):
        print("wrote", os.path.normpath(p))
