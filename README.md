# ntmc

Analysis of **BAKMM-IoD** (Wazid et al., *J. Syst. Archit.* 160 (2025) 103365) and verification of the proposed
improvement **FSL-AKE-IoD**.

## Quick start

```bash
pip install matplotlib pandas pytest nbformat nbconvert jupyter
python -m pytest tests -q                 # 50 tests: correctness, every attack outcome, ablation, hash/bit counts
```

Everything else can be re-run individually:

```bash
cd proposed/code
python attacks_bakmm.py       # original 4 PoC attacks on BAKMM-IoD (from the draft)
python attacks_bakmm_ext.py   # Phase 1: A0-A5, Attack_log items, ES-CS errata, Sec. 7.2 arithmetic
python attacks_fslake.py      # Phase 2: 32 attacks x {BAKMM on_confirm, BAKMM on_send, FSL v1, FSL v2}
python ablation.py            # switch M1-M6 / F2-F4 off one at a time
python cost.py                # instrumented hash counts, bits, SHA-256 and session timing, Table 8/9 comparison
python charts.py              # -> images/fslake_*.png
python diagrams.py            # -> fslake_auth.svg, fslake_architecture.svg
cd ../..
python scripts/build_notebooks.py        # rebuild + execute the four FSL-AKE-IoD notebooks
python scripts/build_walkthrough.py      # rebuild + execute the walkthrough notebook
SCYTHER=/path/to/scyther-linux bash scripts/run_formal.sh   # Scyther + ProVerif (see below)
```

## Repository map

| Path | Content |
|---|---|
| `BAKMM-IoD-*.ipynb`, `Attack_log.ipynb`, `scyther-guide.ipynb`, `resource-guid.ipynb` | Week 2 notes on the paper (unchanged) |
| **`FSL-AKE-IoD-project_walkthrough.ipynb`** | **start here**: plain-language story of the whole project: method, every drawback with a demo, design reasoning, v1 → v2, limits, cost |
| `FSL-AKE-IoD-proposed_protocol.ipynb` | notation, registration, authentication, resynchronisation, ES–CS, diagrams |
| `FSL-AKE-IoD-security_verification.ipynb` | Phase 0 equation diff, Phase 1 verdicts, every Phase 2 attack, ATTACK × PROTOCOL matrix, formal status, ROR sketch |
| `FSL-AKE-IoD-ablation.ipynb` | MODIFICATION × ATTACK matrix |
| `FSL-AKE-IoD-performance.ipynb` | hash counts, bits, timings, Table 8/9 comparison, charts |
| `proposed/code/bakmm_iod.py` | BAKMM-IoD DE–ES (harmonised SK order) — from the draft, unchanged |
| `proposed/code/bakmm_literal.py` | BAKMM-IoD exactly as printed (DE-side SK order) + ES–CS phase m1–m6 with errata switches |
| `proposed/code/proposed_fslake.py` | FSL-AKE-IoD **v1** as supplied with the draft (unchanged; it is what the attacks break) |
| `proposed/code/fslake.py` | FSL-AKE-IoD **v2**: v1 + fixes F1–F4, with ablation switches M1–M6 |
| `tests/test_protocols.py` | one-command regression suite |
| `fslake_auth.spdl`, `fslake_key_mgmt.spdl` | Scyther models of v2 |
| `bakmm_auth_compromise*.spdl`, `fslake_auth_compromise*.spdl` | capture-after-session (forward secrecy) models + control |
| `proverif/*.pv` | ProVerif forward-secrecy models (phase-1 capture) |
| `fslake_auth.dot/.svg`, `fslake_architecture.dot/.svg` | message-flow and architecture diagrams |
| `fslake_technical_analysis.tex`, `main.tex` | Week 3 write-up (Week 2 section kept) |
| `VERIFICATION_LOG.md` | every command, its output and its verdict |

## What still needs a tool that is not installed here

| Step | Status | How to run |
|---|---|---|
| Scyther on all `.spdl` files | NOT RUN | install Scyther 1.1.3+ (<https://people.cispa.io/cas.cremers/scyther/>), then `SCYTHER=.../scyther-linux bash scripts/run_formal.sh`; claim tables go to `images/scyther_*.png` |
| ProVerif forward-secrecy queries | NOT RUN | `opam install proverif`, then the same script (or `proverif proverif/fslake_fs.pv`) |
| `.dot` → `.svg` with Graphviz | NOT RUN (SVGs drawn with matplotlib instead) | `dot -Tsvg fslake_auth.dot -o fslake_auth.svg` |
| LaTeX build of `main.tex` | NOT RUN | `pdflatex main.tex` (note: `bakmm_technical_analysis.tex` uses `\rightarrow` in text mode inside a table, which needs `$...$`) |
