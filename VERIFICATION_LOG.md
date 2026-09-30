# VERIFICATION_LOG — BAKMM-IoD cryptanalysis and FSL-AKE-IoD review

Running log. Each entry records: the command, a summary of its output, and a verdict.

Verdicts: **VERIFIED** (ran and the expected result came out), **FAILED** (ran, and the claim did not hold),
**NOT RUN** (with the reason).

Environment: Windows 11, Python 3.12.0, pytest 8.2.2, matplotlib 3.9.2, nbconvert 7.11.0.
Tools that are **not installed** on this machine (checked with `which` on Windows and in WSL Ubuntu):
Scyther, ProVerif, Graphviz `dot`, LaTeX. `pymupdf` was pip-installed only to render the paper's
equations to images (the PDF text layer drops every math glyph).

Paths are relative to the repository root. `proposed/code` is abbreviated `pc/`.

---

## Phase 0 — Inventory (read only)

| # | Action | Result | Verdict |
|---|---|---|---|
| 0.1 | Read README.md, 8 notebooks, 2 root `.spdl`, 7 `models/*.spdl`, `.dot`, `.tex`, `proposed/code/*` | All notebooks are markdown/LaTeX only (no code cells). `bakmm_attacks.dot` is empty (0 bytes). `NTMC_W2_c.tex` `\input`s a missing `scyther_environment.tex`. | done |
| 0.2 | `pdftotext` + `pymupdf` renders of paper pp. 5–7, 11–14 and of the 11-page draft | Equations are quoted from the rendered images, not the text layer | done |
| 0.3 | Tool check: `which scyther proverif dot pdflatex`; `wsl -d Ubuntu -- which ...` | None found | Scyther/ProVerif/dot/LaTeX steps are **NOT RUN** |

(The full equation diff is in the Phase 0 section of `FSL-AKE-IoD-security_verification.ipynb` and is summarised in the final report.)

---

## Phase 1 — Baseline reproduction (existing scripts, unmodified)

| # | Command | Output summary | Verdict |
|---|---|---|---|
| 1.1 | `cd pc && python attacks_bakmm.py` | capture/verifier/desync/replay all `True` (attack succeeded) | **VERIFIED** (reproduces the draft) |
| 1.2 | `cd pc && python attacks_proposed.py` | capture/verifier/desync/replay/correctness all `True` (resisted) | Reproduces, **but** these 4 tests are too weak (see probe 2.0) |
| 1.3 | inline: 1000 BAKMM sessions per ES update policy | `on_confirm 1000/1000`, `on_send 1000/1000` key agreement | **VERIFIED** (with the *harmonised* SK order; see 1.x in the extended runs) |

## Phase 2 — first probes against the proposal (v1 = `pc/proposed_fslake.py`, unmodified)

| # | Probe | Output | Verdict |
|---|---|---|---|
| 2.0a | Two drones enrolled with default `enroll()`; A runs a session; then B | `drone B after A's session: ES: unknown TID` | **FAILED** (bug in v1: every drone gets `dev="DE"`, so A's session deletes B's record) |
| 2.0b | Drone clock +1 s (within ΔT=2); genuine session; replay MSG1 at ES time r+3 | `replay accepted after cache expiry`; genuine drone then `ES: unknown TID` | **FAILED** (v1 cache expires at receive time + ΔT instead of T1 + ΔT, so replay leads to permanent de-sync) |
| 2.0c | Drone retries MSG1 (a, b) within ΔT; adversary delivers b, then a | genuine drone then `ES: unknown TID` | **FAILED** (v1 dual record deletes the record the drone actually holds) |


## Phase 1 — Extended BAKMM-IoD checks (`pc/attacks_bakmm_ext.py`)

| # | Command | Output summary | Verdict |
|---|---|---|---|
| 1.4 | `python attacks_bakmm_ext.py` → A0 | printed SK orders (AKDDE2 vs AKDDE3/Table 5): **0/1000** sessions agree | **VERIFIED**: spec erratum is real (Attack_log item 1 correct) |
| 1.5 | A0b | harmonised order: on_confirm 1000/1000, on_send 1000/1000 | **VERIFIED** (correctness) |
| 1.6 | A1 capture | 5/5 past SKs, 3/3 future SKs, all 5 TIDs linked | **VERIFIED**: CONFIRMED under the paper's own §3.2 threat model |
| 1.7 | A2 stolen verifier | ES record fields = [MS, RID]; 3/3 drones impersonated with random TC_DE | **VERIFIED**: CONDITIONAL on reading the ES DB (Prop. 4 assumes access control prevents it); "TC_DE never checked" is unconditional |
| 1.8 | A3 de-sync | on_confirm: drop MSG3 → locked; on_send: drop MSG2 → locked; the other drops recover | **VERIFIED**: both policies fail |
| 1.9 | A4 replay in ΔT | on_confirm: accepted, genuine M6 then fails, drone locked; on_send: replay rejected (TID already rotated) | **VERIFIED**: acceptance depends on policy; lock-out CONDITIONAL on single pending slot |
| 1.10 | **A5 (new)** flip 1 bit of MSG2.M5 | both sessions "succeed", then drone locked out (both policies) | **VERIFIED**: M5 is not authenticated by M4 (contradicts Prop. 2 / ASFF2) |
| 1.11 | AL3 / AL4 / AL5 | replay after 2ΔT rejected; drift > ΔT rejected (DoS); 0/1000 ESL guesses | **VERIFIED** as Attack_log expects |
| 1.12 | E (ES–CS as printed) | corrected: 2/2 sessions; E1 m1/m2 order: session 1 fails at CS m2; E4 RS2 in TIN: session 1 ok, session 2 "unknown TIN" | **VERIFIED**: printed ES–CS phase does not work |
| 1.13 | C (§7.2) | 704 + 800 + 288 = 1792 = Table 9; "2880"/"1782" are typos; M5 as 160 bits gives 1696 | **VERIFIED** |

## Phase 2 — Attack matrix (`pc/attacks_fslake.py`) and fixes

| # | Command | Output summary | Verdict |
|---|---|---|---|
| 2.1 | `python attacks_fslake.py` (32 attacks × BAKMM[on_confirm], BAKMM[on_send], FSL-v1, FSL-v2) | see matrix in `FSL-AKE-IoD-security_verification.ipynb` | **VERIFIED** (all ran) |
| 2.2 | FSL-v1 failures | replay + skew → lock-out; replay after ES reboot → lock-out; reordered retry → lock-out; 6 withheld retries → lock-out; 2nd drone deleted by `enroll()` default; naive revocation leaves old record; 47/160 sessions fail with 8-bit TIDs (dict overwrite) | **FAILED** (proposal v1 as written is not viable) |
| 2.3 | FSL-v2 (`pc/fslake.py`, fixes F1–F4 + reboot quiet period + collision-tolerant lookup) | every one of the above RESISTED; remaining SUCCEEDED rows are KCI after capture and future SKs after capture (both inherent to symmetric-only AKE) | **VERIFIED** |
| 2.4 | Self-review of fix F3 | bounded candidate list can be evicted by ≥5 withheld retries → added F4 (drone retry gap > 2ΔT) | **VERIFIED** after F4 |
| 2.5 | Anonymity | successful sessions unlinkable; each dropped MSG2 → retry reuses TID (4 linkable pairs / 12) in BAKMM, v1 and v2; optional `retry_pseudonyms=3` → 0 repeats (ES cost 7 → 10 h) | **VERIFIED** (draft's "cannot link sessions" is an overclaim) |
| 2.6 | `python ablation.py` | M1 → FS + TID linking; M2 → anonymity + linking; M3 → drop-one de-sync; M4 → replay (+ skew); M5 → stolen DB; **M6 → nothing re-opens** (and adding MSG3 lowers ES-compromise exposure 3/15 → 0/15); F2 → skew replay; F3 → reorder + eviction; F4 → eviction | **VERIFIED** |

## Phase 4 — Cost (`pc/cost.py`)

| # | Command | Output summary | Verdict |
|---|---|---|---|
| 4.1 | instrumented hash counts | BAKMM DE 8 (3+5), ES 8 (7+1); FSL v1 5/7; FSL v2 5/7; BAKMM ES–CS 8/8 | **VERIFIED**: 8/8 and 5/7 |
| 4.2 | bits | BAKMM 704+800+288 = 1792 (M5 counted as 256, as the paper does; 1696 if 160); FSL 608+448 = 1056 | **VERIFIED** |
| 4.3 | 10^5 × SHA-256 on this machine | h(): 6.9 µs mean, 30.2 µs std (OS noise; median lower); raw hashlib 64 B: 1.7 ± 6.3 µs | **VERIFIED** (machine-specific) |
| 4.4 | Table 8 comparison with paper T_h | FSL drone 5T_h = 1.545 ms (cheapest); server 7T_h = 0.385 ms, **worse than Algarni & Jan (6T_h = 0.33 ms)** and equal to Mishra (7T_h); bits 1056 (cheapest) | **VERIFIED**: not strictly cheaper on the server |
| 4.5 | TID collision bound | 2·10^12 pseudonyms, P ≤ G²/2^161 ≈ 1.4·10^-24 | **VERIFIED** (analytic) |

## Phase 3 — Formal verification

| # | Item | Result | Verdict |
|---|---|---|---|
| 3.1 | Scyther on `bakmm_auth.spdl`, `bakmm_key_mgmt.spdl`, `pc/fslake_iod.spdl`, `fslake_auth.spdl`, `fslake_key_mgmt.spdl` | Scyther not installed (Windows PATH and WSL Ubuntu checked) | **NOT RUN** |
| 3.2 | Compromise models `bakmm_auth_compromise.spdl` (expected Secret SK **Fail**), `bakmm_auth_compromise_xorfun.spdl` (expected **Ok = false negative**), `fslake_auth_compromise.spdl` (expected **Ok**), `fslake_auth_compromise_control.spdl` (expected Fail) | written; the SPDL syntax is not machine-checked | **NOT RUN** (the Python equivalents A1 / `capture_past_keys` are VERIFIED) |
| 3.3 | ProVerif `proverif/bakmm_fs.pv`, `proverif/fslake_fs.pv` (phase-1 capture, `query attacker(secret…)`) | ProVerif not installed | **NOT RUN** |
| 3.4 | ROR proof sketch | markdown in `FSL-AKE-IoD-security_verification.ipynb` and in the tex | written (a sketch, not machine-checked) |
| 3.5 | `bash scripts/run_formal.sh` dry run | prints "NOT RUN: Scyther not found", "NOT RUN: ProVerif not found" | runner **VERIFIED** to degrade cleanly |

Observation (analytical, from reading): the paper's Fig. 3/4 and all BAKMM `.spdl` files declare `const xor: Function`
(uninterpreted), so Scyther cannot model un-masking and cannot find A1 at any bound.

## Phase 5 — Artefacts

| # | Command | Result | Verdict |
|---|---|---|---|
| 5.1 | `python scripts/build_notebooks.py` (nbconvert --execute) | 4 notebooks, 35 code cells, 0 errors, 0 unexecuted | **VERIFIED** |
| 5.2 | `python charts.py`, `python diagrams.py` | `images/fslake_{comm,drone,server}_cost.png`, `images/fslake_hash_counts.png`, `fslake_auth.svg`, `fslake_architecture.svg` | **VERIFIED** (rendered and inspected) |
| 5.3 | `python -m pytest tests -q` (5 repeated runs + final) | 50 passed every time | **VERIFIED** |
| 5.4 | `pdflatex main.tex` | LaTeX not installed. Also: the existing `bakmm_technical_analysis.tex` lines 129–133 use `\rightarrow` in text mode (needs `$…$`) | **NOT RUN** |
| 5.5 | `python scripts/build_walkthrough.py` | `FSL-AKE-IoD-project_walkthrough.ipynb`: 66 cells, all executed, 0 errors; demo outputs match the text | **VERIFIED** |
