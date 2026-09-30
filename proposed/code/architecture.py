"""Draws the system architecture of the proposed FSL-AKE-IoD (fig_architecture.png)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

fig, ax = plt.subplots(figsize=(11, 5.6)); ax.set_xlim(0, 11); ax.set_ylim(0, 5.6); ax.axis("off")


def box(x, y, w, hgt, title, body, fc):
    ax.add_patch(FancyBboxPatch((x, y), w, hgt, boxstyle="round,pad=0.05,rounding_size=0.12",
                                fc=fc, ec="#333", lw=1.1))
    ax.text(x + w / 2, y + hgt - 0.25, title, ha="center", va="top", fontsize=10, weight="bold")
    ax.text(x + w / 2, y + hgt - 0.6, body, ha="center", va="top", fontsize=7.6, linespacing=1.35)


def arrow(x1, y1, x2, y2, label, both=True, dy=0.12, style="-"):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="<|-|>" if both else "-|>", lw=1.3, ls=style, color="#222"))
    ax.text((x1 + x2) / 2, (y1 + y2) / 2 + dy, label, ha="center", fontsize=7.5, color="#1f3b73")


box(0.2, 0.6, 2.5, 3.2, "Drones  DE_i",
    "stores {TID_i , K_i}\n\nper session:\n5 hash ops\n\nafter session:\nK_i <- h(K_i || SK)\nTID_i <- h(TID_i || SK)\nold K erased\n(forward secrecy)", "#e8f1ff")
box(4.1, 0.6, 2.9, 3.2, "Ground Station  ES_j",
    "secure element: X_ES\nDB: TID -> C = K XOR h(X_ES||TID)\n(old + cur record per drone)\nreplay cache (TID,T1,N1) for dT\n\nper session: 7 hash ops\nbuilds partial blocks PB\n(ECC-encrypted, ECDSA-signed)", "#fff4e0")
box(8.3, 0.6, 2.5, 3.2, "Cloud Servers  CS_k",
    "P2P blockchain network\nminers + PBFT/consensus\n\nverifies ECDSA on PB,\nadds block to ledger\n\nES<->CS keys via the same\nFSL-AKE exchange\n(ES = initiator)", "#e9f7ef")
box(3.6, 4.35, 3.9, 1.05, "Registration Authority (RA) - offline",
    "issues {TID_i, K_i} to drones, masked C_i to ES;\nadds/revokes drones (dynamic addition)", "#f3e8ff")

arrow(2.75, 2.75, 4.05, 2.75, "MSG1 {TID, N1, T1, V1}  608 b", both=False)
arrow(4.05, 2.05, 2.75, 2.05, "MSG2 {N2, T2, V2}  448 b", both=False)
ax.text(3.4, 1.45, "SK = h(K||N1||N2||T1||T2||TID)", ha="center", fontsize=7.2, style="italic")
arrow(7.05, 2.75, 8.25, 2.75, "FSL-AKE (2 msgs)", both=False)
arrow(8.25, 2.05, 7.05, 2.05, "SK_ES,CS", both=False)
arrow(7.05, 1.2, 8.25, 1.2, "E_SK(partial blocks)", both=False)
arrow(5.55, 4.3, 5.55, 3.9, "", both=False, style="--")
arrow(4.2, 4.6, 1.5, 3.9, "secure offline channel", both=False, style="--", dy=0.15)
arrow(6.9, 4.6, 9.5, 3.9, "", both=False, style="--")
ax.text(5.5, 0.2, "Open wireless channel: Dolev-Yao / CK adversary (eavesdrop, drop, replay, capture drone, steal ES DB)",
        ha="center", fontsize=8, color="#8a1c1c")
plt.tight_layout(); plt.savefig("fig_architecture.png", dpi=200)
print("wrote fig_architecture.png")
