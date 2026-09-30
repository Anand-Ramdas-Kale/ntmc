"""Render a Scyther command-line result file as a claim table PNG (like the paper's Fig. 5).

    python formal_report.py formal_results/fslake_auth.txt images/scyther_fslake_auth.png

Scyther prints one line per claim, tab separated, e.g.
    claim   FSLAKE,DE1   Secret h(k(DE,ES),N1,N2,T1,T2,TID)   Ok   [no attack within bounds]
"""
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def parse(path):
    rows = []
    for line in open(path, encoding="utf-8", errors="replace"):
        parts = [p.strip() for p in line.rstrip("\n").split("\t") if p.strip()]
        if len(parts) >= 4 and parts[0] == "claim":
            status = next((p for p in parts if p in ("Ok", "Fail")), "?")
            comment = parts[-1] if parts[-1] not in ("Ok", "Fail") else ""
            rows.append([parts[1], parts[2][:60], status, comment])
    return rows


def render(rows, out, title):
    fig, ax = plt.subplots(figsize=(11, 0.42 * len(rows) + 1.2))
    ax.axis("off")
    ax.set_title(title, loc="left", fontsize=10)
    tab = ax.table(cellText=rows, colLabels=["Claim", "Type / term", "Status", "Comment"],
                   cellLoc="left", colLoc="left", loc="upper left",
                   colWidths=[0.16, 0.46, 0.08, 0.30])
    tab.auto_set_font_size(False)
    tab.set_fontsize(8)
    for (r, c), cell in tab.get_celld().items():
        cell.set_edgecolor("#c8c8c8")
        if r == 0:
            cell.set_text_props(weight="bold")
        elif c == 2:
            cell.set_text_props(color="#1a7f37" if rows[r - 1][2] == "Ok" else "#cf222e", weight="bold")
    plt.tight_layout()
    plt.savefig(out, dpi=160)


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    rows = parse(src)
    if not rows:
        print(f"no claim lines in {src} (did Scyther run?)")
        sys.exit(1)
    render(rows, dst, src)
    print(f"wrote {dst} ({len(rows)} claims)")
