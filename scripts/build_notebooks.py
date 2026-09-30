"""Builds the four FSL-AKE-IoD notebooks (description -> code -> output explanation, like the
existing BAKMM-IoD notebooks) and executes them so outputs are stored.

    python scripts/build_notebooks.py            (then they are executed with nbconvert)
"""
import os
import subprocess
import sys

import nbformat as nbf

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SETUP = """import sys, os
sys.path.insert(0, os.path.join(os.getcwd(), "proposed", "code"))
import pandas as pd
pd.set_option("display.max_colwidth", 200)
from common import Clock, AuthError, h, xor, size_bits, reset_hash_counter, hashes"""


def md(s):
    return nbf.v4.new_markdown_cell(s.strip("\n"))


def code(s):
    return nbf.v4.new_code_cell(s.strip("\n"))


def notebook(cells):
    nb = nbf.v4.new_notebook()
    nb["cells"] = cells
    nb["metadata"]["kernelspec"] = {"display_name": "Python 3", "language": "python", "name": "python3"}
    return nb


# ============================================================================ 1. protocol
PROTOCOL = [
    md(r"""
# FSL-AKE-IoD — Proposed Protocol (v2, after independent review)

$\text{Forward-Secure, Lightweight, desynchronisation-resilient AKE between drone }DE_i\text{ and ground station }ES_j$

This notebook describes the protocol **as it stands after the review** (`proposed/code/fslake.py`).
The message formulas are the ones in the Week 3 draft and in `proposed_fslake.py` (v1).
The review found flaws in v1 and fixed them. Each fix is marked **F1–F4** below; the attacks that motivate them are in
`FSL-AKE-IoD-security_verification.ipynb`.

| | v1 (draft) | v2 (this notebook) |
|---|---|---|
| F1 | `enroll()` gives every drone `dev="DE"`, so one drone's session deletes all the others | unique device id per drone |
| F2 | replay-cache entry kept until *receive time* + $\Delta T$ | kept until $T_1+\Delta T$ (the whole acceptance window) |
| F3 | exactly one *old* + one *cur* record | *anchor* (last proven key) + *candidates*; promote on proof of possession |
| F4 | drone may re-send MSG1 at any time | drone waits $>2\Delta T$ before re-sending on the same credentials |
| — | no reboot handling | ES refuses MSG1 for $2\Delta T$ after losing its cache; collision-tolerant TID lookup |
"""),
    code(SETUP + "\nimport fslake as F\nprint(F.V2)"),
    md("""
**Output explanation.** `F.V2` is the full protocol: the six design modifications M1–M6 of the draft and the four
review fixes F2–F4 are all switched on. The ablation notebook switches them off one at a time.
"""),
    md(r"""
## Notation

$$
\begin{aligned}
K_i&\colon\;\text{current 256-bit key shared by }DE_i\text{ and }ES_j\text{ (evolves every session)}\\
TID_i&\colon\;\text{160-bit one-time pseudonym (evolves every session, never sent in advance)}\\
X_{ES}&\colon\;\text{256-bit master secret of }ES_j\text{, kept in a secure element (TPM/HSM)}\\
C_i&=K_i\oplus h(X_{ES}\parallel TID_i)\colon\;\text{masked verifier stored in the ES database}\\
N_1,N_2&\colon\;\text{160-bit nonces (public)}\qquad T_1,T_2\colon\;\text{32-bit timestamps}\\
\Delta T&\colon\;\text{maximum transmission delay}\qquad h(\cdot)\colon\;\text{SHA-256 over a length-prefixed concatenation}
\end{aligned}
$$
"""),
    md(r"""
## Registration (RA, offline, secure channel)

* $RA$ picks $K_i$ (256 bit), $TID_i$ (160 bit) and an internal device id $dev_i$ (**F1**).
* $DE_i$ stores $\{TID_i, K_i\}$ (52 bytes).
* $ES_j$ stores the *anchor* record $\{dev_i, TID_i, C_i = K_i\oplus h(X_{ES}\parallel TID_i)\}$ and discards $K_i$.
* The RA must erase $K_i$ after provisioning (otherwise it is a privileged insider — see the security notebook).
"""),
    code("""
ra = F.RA(); clock = Clock(); es = F.GroundStation(clock)
creds = [ra.register_drone() for _ in range(2)]
for c in creds:
    es.enroll(c)
drones = [F.Drone(c, clock) for c in creds]
print("drone memory:", {k: (v.hex()[:16] + '...', len(v)) for k, v in drones[0].mem.items()})
print("ES records  :")
for dev, d in es.devs.items():
    print(f"  {dev}: anchor TID={d['anchor']['TID'].hex()[:12]}..  C={d['anchor']['C'].hex()[:16]}..  candidates={len(d['cands'])}")
print("C == K ?", es.devs[creds[0]['dev']]['anchor']['C'] == creds[0]['K'])
"""),
    md("""
**Output explanation.** Each drone holds only its pseudonym and key (20 + 32 bytes). The ES stores one anchor record
per drone, keyed by a unique device id. The stored value `C` differs from `K`: without `X_ES` it is a uniformly random
string.
"""),
    md(r"""
## Authentication and key establishment (2 messages)

**Step 1 — $DE_i\rightarrow ES_j$.** Pick $N_1, T_1$; $V_1 = h(K\parallel TID\parallel N_1\parallel T_1)$;
$MSG_1=\{TID, N_1, T_1, V_1\}$ (160+160+32+256 = 608 bits).

**Step 2 — $ES_j$.**
* check $|T_1-T_1^*|\le\Delta T$ and $(TID,T_1,N_1)\notin$ cache (entry kept until $T_1+\Delta T$, **F2**)
* for each record stored under $TID$: $K = C\oplus h(X_{ES}\parallel TID)$, check $V_1$
* pick $N_2,T_2$; $SK=h(K\parallel N_1\parallel N_2\parallel T_1\parallel T_2\parallel TID)$; $V_2=h(SK\parallel N_2\parallel T_2)$
* $MSG_2=\{N_2,T_2,V_2\}$ (160+32+256 = 448 bits)
* $K'=h(K\parallel SK)$, $TID'=h(TID\parallel SK)_{[0..159]}$, store $C'=K'\oplus h(X_{ES}\parallel TID')$:
  if the matched record is the **anchor**, add $(TID',C')$ as a **candidate**; if it is a **candidate**, the drone has
  proved it holds it, so promote it to anchor and drop everything else (**F3**).

**Step 3 — $DE_i$.** Check $|T_2-T_2^*|\le\Delta T$, recompute $SK$, check $V_2$; then
$K\leftarrow h(K\parallel SK)$, $TID\leftarrow h(TID\parallel SK)$, erase $N_1$ and the old $K$.
"""),
    code("""
de = drones[0]
reset_hash_counter(); m1 = de.start(); h_de1 = hashes(); clock.advance()
reset_hash_counter(); m2, sk_es = es.respond(m1); h_es = hashes(); clock.advance()
reset_hash_counter(); sk_de = de.finish(m2); h_de2 = hashes()
print("MSG1:", {k: (v if isinstance(v, int) else v.hex()[:12] + '..') for k, v in m1.items()}, size_bits(m1), "bits")
print("MSG2:", {k: (v if isinstance(v, int) else v.hex()[:12] + '..') for k, v in m2.items()}, size_bits(m2), "bits")
print("hashes: DE", h_de1 + h_de2, " ES", h_es)
print("SK agree:", sk_de == sk_es, "  drone TID changed:", de.TID != m1['TID'])
d = es.devs[creds[0]['dev']]
print("ES after session: anchor TID == old TID:", d['anchor']['TID'] == m1['TID'],
      "| candidate TID == drone's new TID:", d['cands'][0]['TID'] == de.TID)
"""),
    md("""
**Output explanation.** The two messages are 608 + 448 = 1056 bits. Instrumentation counts 5 hash operations on the
drone (V1, SK, V2, K', TID') and 7 on the ES (unmask, V1, SK, V2, K', TID', mask). Both sides derive the same SK.
The drone's next pseudonym never appears on the air. The ES keeps the old key as the anchor until the drone proves,
in its next session, that it holds the candidate.
"""),
    md(r"""
## Resynchronisation (lost MSG2) and the retry rule F4

If $MSG_2$ is lost, the drone still holds the anchor credentials. Its next $MSG_1$ matches the anchor, and the ES adds
another candidate; nothing is deleted, so no ordering of deliveries can remove the record the drone actually holds.
The drone may only re-send on the same credentials after $2\Delta T$ (**F4**). Then at most one of its $MSG_1$ is
fresh at the ES at any time, so the bounded candidate list can never be flooded with withheld retries.
"""),
    code("""
de = drones[1]
tr, a, b = F.run_session(de, es, clock, drop="MSG2")
d = es.devs[creds[1]['dev']]
print("after dropped MSG2 -> drone still on anchor:", de.TID == d['anchor']['TID'], "| candidates:", len(d['cands']))
try:
    de.start()
except AuthError as e:
    print("immediate retry:", e)
clock.advance(2 * F.DELTA_T + 1)
tr, a, b = F.run_session(de, es, clock)
print("retry after 2dT: keys agree =", a == b, "| candidates now:", len(d['cands']))
clock.advance(10)
tr, a, b = F.run_session(de, es, clock)
print("next session (drone proves candidate -> promoted): keys agree =", a == b,
      "| anchor == TID the drone just used:", d['anchor']['TID'] == tr['MSG1']['TID'], "| candidates:", len(d['cands']))
"""),
    md("""
**Output explanation.** After the drop, the drone is still on the anchor. An immediate retry is refused by rule F4.
The retry after 2ΔT succeeds, and the ES now holds two candidates. When the drone next authenticates with the one it
accepted, that candidate becomes the anchor and the stale candidate is deleted. No extra message is needed.
"""),
    md(r"""
## Replay cache, reboot and revocation

* The cache stores $(TID,T_1,N_1)$ only **after** a valid $V_1$, so forged messages cannot fill it.
* After a reboot (cache lost) the ES refuses every $MSG_1$ for $2\Delta T$, so every message it might have cached is stale.
* Revocation deletes the anchor **and** all candidates of the device.
"""),
    code("""
de = drones[0]
m1 = de.start(); m2, _ = es.respond(m1); de.finish(m2)
try: es.respond(dict(m1))
except AuthError as e: print("replay:", e)
es.reboot()
try: es.respond(dict(m1))
except AuthError as e: print("replay right after reboot:", e)
clock.advance(2 * F.DELTA_T + 1)
try: es.respond(dict(m1))
except AuthError as e: print("replay after the quiet period:", e)
es.revoke(creds[0]['dev'])
try: F.run_session(de, es, clock)
except AuthError as e: print("revoked drone:", e)
"""),
    md("""
**Output explanation.** The replay is caught by the cache. Right after a reboot it is caught by the quiet period, and
after the quiet period its timestamp is stale. A revoked drone has no record left under any identifier.
"""),
    md(r"""
## ES–CS key management

The same two-message exchange runs with $ES_j$ as initiator and $CS_k$ as responder; $CS_k$ holds its own $X_{CS}$.
The resulting $SK_{ES,CS}$ protects partial blocks. The ECC/ECDSA blockchain phase of BAKMM-IoD is unchanged.
(For comparison, the ES–CS phase *as printed* in BAKMM-IoD fails; see the security notebook, check **E**.)
"""),
    code("""
ra_c = F.RA(); cs = F.Responder(clock)            # cloud server = responder
cred_es = ra_c.register_drone(); cs.enroll(cred_es)
es_init = F.Initiator(cred_es, clock)             # ground station = initiator
for i in range(3):
    tr, a, b = F.run_session(es_init, cs, clock); clock.advance(30)
    print(f"ES-CS session {i+1}: SK_ES,CS agree = {a == b}, TIN on air = {tr['MSG1']['TID'].hex()[:12]}..")
"""),
    md("""
**Output explanation.** Three ES–CS sessions succeed, and each uses a fresh pseudonym (TIN). Key evolution gives the
ES–CS link the same forward secrecy as the drone link.
"""),
    md("""
## Sequence and architecture diagrams

Graphviz sources: `fslake_auth.dot`, `fslake_architecture.dot`. Graphviz is not installed on the authoring machine, so
the SVGs below were drawn by `proposed/code/diagrams.py` from the same content.

<img src="./fslake_auth.svg" width="900" alt="FSL-AKE-IoD message flow">

<img src="./fslake_architecture.svg" width="900" alt="FSL-AKE-IoD architecture">
"""),
]

# ============================================================================ 2. security
EQ_DIFF = r"""
## Phase 0 — Equation diff: paper vs notebooks vs code vs .spdl

Formulas were read from rendered images of the paper (pp. 5–7), because the PDF text layer drops the math glyphs.
$A = h(TC_{DE}\parallel rs_1\parallel MS\parallel T_1)$, $B = h(RID_{ES}\parallel TC_{ES}\parallel rs_2\parallel MS\parallel T_2)$.

| Item | Paper (as printed) | Notebooks | `bakmm_iod.py` | `.spdl` models | Mismatch |
|---|---|---|---|---|---|
| M1 | $h(RID_{DE}\parallel MS\parallel T_1)\oplus A$ | same | same | same | – |
| M2 | $h(A\parallel RID_{DE}\parallel T_1)$ | same | same | same | – |
| M3 | $h(RID_{DE}\parallel MS\parallel T_2)\oplus B$ | same | same | same | – |
| **SK (ES, AKDDE2)** | $h(A\parallel B\parallel T_1\parallel T_2\parallel RID_{DE}\parallel MS)$ | same | same | same | – |
| **SK (DE, AKDDE3 + Table 5)** | $h(A\parallel B\parallel RID_{DE}\parallel T_1\parallel T_2\parallel MS)$ | **ES order** | **ES order** | **ES order** | **yes — printed protocol never agrees (A0)**; Attack_log item 1 is right |
| M4 | $h(SK\parallel T_1\parallel T_2\parallel RID_{DE})$ | same | same | same | – |
| M5 | $TID^{new}\oplus h(A\parallel RID_{DE}\parallel T_2)$ | same | same, hash truncated to 160 bit | same | 160-bit TID XOR 256-bit hash; §7.2 counts M5 as 256 bit |
| M6 | $h(SK\parallel T_3)$ | same | same | same | – |
| TID update at ES | "generates a new temporary identity"; **when** the ES overwrites is not stated | not stated | parameter `on_send` / `on_confirm` | not modelled | unspecified in paper |
| m1 | $h(TC_{ES}\parallel RS_1\parallel MS\parallel TS_1)\oplus h(RID_{ES}\parallel MS\parallel TS_1)$ | $h(RS_1\parallel TC_{ES}\ldots)$ (silently re-ordered) | **not implemented** | `03_*`: printed order | **inner order differs from m2 (E1)** |
| m2 | $h(h(RS_1\parallel TC_{ES}\parallel MS\parallel TS_1)\parallel RID_{ES}\parallel MS\parallel TS_1)$; CS check uses "$rs_1$" | same ($RS_1$) | not impl. | same | "rs1" typo (E2) |
| m3 | $h(RS_2\parallel TC_{CS}\parallel MS_{ES_j-ES_j}\parallel TS_2)\oplus h(RID_{ES}\parallel MS\parallel TS_1\parallel TS_2)$ | $MS_{ES-CS}$ | not impl. | $MS_{ES-CS}$ | "$MS_{ES_j-ES_j}$" typo (E3) |
| SK$_{ES,CS}$ | $h(h(RS_2\ldots)\parallel h(RS_1\ldots)\parallel RID_{ES}\parallel MS\parallel TS_1\parallel TS_2)$ | same | not impl. | same | – |
| m4 | $h(SK\parallel RID_{ES}\parallel MS\parallel TS_2)$ | uses $T_2$ (typo) | not impl. | same | notebook typo |
| m5 / TIN recovery | CS: $TIN^{new}\oplus h(RID_{ES}\parallel h(RS_1\parallel TC_{ES}\ldots)\parallel TS_2)$; **ES: $m_5\oplus h(RID_{ES}\parallel h(RS_2\parallel TC_{ES}\parallel MS\parallel TS_1)\parallel TS_2)$** | ES uses $RS_1$ (silently fixed) | not impl. | ES uses $RS_1$ | **ES cannot know $RS_2$ (E4)** |
| m6 | $h(SK\parallel TS_3)$ | same | not impl. | same | – |
| Root `bakmm_auth.spdl` | – | – | – | declares `rs1, rs2` both as `const` and as `fresh`/`var`; `T1..T3` as `const` | likely rejected by Scyther / timestamps not fresh |
| Root `bakmm_key_mgmt.spdl` | – | – | – | receives `var m3, m4, m5` unconstrained | checks not modelled (as `models/README.txt` warns) |
| All BAKMM `.spdl` | XOR | – | – | `const xor: Function` (uninterpreted) | intruder can never unmask; capture attack is invisible to Scyther |

**Draft (Week 3) vs paper.** The draft's §3.1 formulas match the ES-side order and do not mention the printed DE-side
order. Its "$|MSG_3| = 2880$" and "1782 instead of 1792" statements are confirmed (check **C**).
"""

SEC = [
    md(r"""
# FSL-AKE-IoD — Security Verification

Independent verification of the claimed BAKMM-IoD flaws (Phase 1), the adversarial review of FSL-AKE-IoD (Phase 2),
the formal-verification status (Phase 3), and a proof sketch.

Every result in this notebook comes from running `proposed/code/*.py`. Labels: **VERIFIED** (ran and passed),
**FAILED** (ran and the claim did not hold), **NOT RUN** (with the reason).
"""),
    code(SETUP + "\nimport attacks_fslake as A, attacks_bakmm_ext as X, fslake as F\nIMPLS = A.impls()\n"
         "def show(*attacks):\n    rows = []\n    for a in attacks:\n        for i in IMPLS:\n            r = a(i); rows.append(dict(attack=r.attack, protocol=r.protocol, outcome=r.outcome, reason=r.reason))\n"
         "    return pd.DataFrame(rows)"),
    md("""
**Output explanation.** There are four protocol columns: BAKMM-IoD with the ES updating TID on MSG3 (`BAKMM`) and on
MSG2 (`BAKMM[on_send]`), since the paper does not say which; FSL-AKE-IoD **v1** exactly as supplied with the draft
(`proposed_fslake.py`); and **v2** (`fslake.py`). The outcome is stated from the adversary's side: SUCCEEDED means the
attack works.
"""),
    md(EQ_DIFF),
    md(r"""
# Phase 1 — BAKMM-IoD claims re-checked

Threat model used (paper §3.2): Dolev–Yao (messages "can be accessed, modified, or deleted"), the CK model (session
states and keys can be revealed), and "$\mathcal{A}$ may also physically capture a certain number of drones and extract
data from their memory using an advanced power analysis method".
"""),
    code("""
P1 = pd.DataFrame(X.run_all())
P1[["id", "title", "verdict"]]
"""),
    code("""
for r in X.run_all():
    print(f"{r['id']}: {r['title']}\\n   contradicts: {r['contradicts']}\\n   assumption : {r['assumption']}\\n   evidence   : {r['evidence']}\\n")
"""),
    md(r"""
**Output explanation (per check).**

* **A0** The paper's own SK formulas differ between the ES (AKDDE2) and the drone (AKDDE3 / Table 5), so with the
  printed formulas 0/1000 sessions agree. All of this repository's artefacts use the ES-side order on both sides (A0b,
  1000/1000). This is a specification erratum, not an attack.
* **A1 — CONFIRMED.** The masks $h(RID_{DE}\parallel MS\parallel T_x)$ depend only on static drone secrets and public
  timestamps, so capture gives every past and future SK and the whole TID chain (via M5). It contradicts Prop. 5,
  ASFF8, ASFF13 and §3.2 ("supports forward secrecy"). The draft also cites **ASFF10**; that is an over-reach, because
  ESL of $rs_1, rs_2$ alone is resisted (AL5).
* **A2 — CONDITIONAL.** It works as soon as the ES table is read, but the paper's Prop. 4 assumes access control
  prevents this, and §3.2 does not list ES compromise. "TC_DE is never checked" is unconditional: RSES2 does not even
  store $TC_{DE}$.
* **A3 — CONFIRMED** under both update readings (on_confirm: drop MSG3; on_send: drop MSG2). The paper makes no
  availability claim, but its DY model allows deletion.
* **A4 — acceptance CONFIRMED for on_confirm, REFUTED for on_send** (after MSG2 the old TID is already gone). The
  lock-out consequence also needs a single pending slot, which the paper does not specify.
* **A5 — NEW, CONFIRMED.** M4 authenticates SK but not M5. Flipping one bit of M5 makes the drone store a wrong
  TID while both sides report success, so the drone is locked out for good. This contradicts Prop. 2 ("it is not
  feasible for $\mathcal{A}$ to make any changes in the transmitted messages") and ASFF2.
* **E** The ES–CS phase as printed does not run: m1 and m2 use different inner-hash orders (the CS m2 check fails),
  and the ES's TIN recovery needs $RS_2$, which only the CS knows (session 1 succeeds, session 2 fails).
* **C** 704 + 800 + 288 = **1792** = Table 9. The paper's printed "2880" and "1782" are typos. The existing
  `bakmm_technical_analysis.tex` value of 1696 comes from counting M5 as 160 bits; it is not a paper error.
"""),
    md(r"""
### Exact paper text for the errata (quoted from the rendered PDF)

* §7.2: "*$|MSG_1|$ = 160+256+256+32 = 704 bits, $|MSG_2|$ = 256+256+256+32 = 800 bits, and $|MSG_3|$ = 256+32 = 2880 bits, as a whole the communication of the BAKMM-IoD becomes 704+ 800+ 288 = 1782 bits.*" (Table 9: 1792.)
* AKDEC1: "*$m_1 = h(TC_{ES_j}\| RS_1\| MS_{ES_j-CS_k}\| TS_1)\oplus h(RID_{ES_j}\| MS_{ES_j-CS_k}\| TS_1)$ and $m_2 = h(h(RS_1\| TC_{ES_j}\| MS_{ES_j-CS_k}\| TS_1)\| RID_{ES_j}\| MS_{ES_j-CS_k}\| TS_1)$*"
* AKDEC2: "*$m'_2 = h(h(rs_1\| TC_{ES_j}\| MS_{ES_j-CS_k}\| TS_1)\| \ldots$*" and "*$m_3 = h(RS_2\| TC_{CS_k}\| MS_{ES_j-ES_j}\| TS_2)\oplus h(RID_{ES_j}\| MS_{ES_j-CS_k}\| TS_1\|TS_2)$*"
* AKDEC3: "*Further, $ES_j$ computes $TIN^{new}_{CS_k} = m_5 \oplus h(RID_{ES_j}\| h(RS_2\| TC_{ES_j}\| MS_{ES_j-CS_k}\| TS_1)\|$ $TS_2)$*"
* Other errata found: Prop. 1 is titled "*The SBBDA-IoD protocol makes it impossible to execute a replay attack*" (wrong scheme name); Table 10 marks BAKMM-IoD **×** for ASFF9 (formal verification) although §6 uses Scyther.
"""),
    md("""
### Cross-check with `Attack_log.ipynb`

| Attack_log item | Covered by | Result here | Agreement |
|---|---|---|---|
| 1 SK concatenation-order mismatch | A0 | 0/1000 agree with the printed formulas | agrees |
| 2 De-sync by dropping MSG3 (ES commits on MSG3) | A3 | locked out; the on_send reading fails by dropping MSG2 instead | agrees, extended |
| 3 Replay after 2ΔT rejected | AL3 | rejected (stale T1) | agrees; the log misses the **in-window** replay (A4) |
| 4 Clock drift / GPS spoofing DoS | AL4, `delta_t_edges` | rejected beyond ΔT; affects FSL-AKE-IoD equally | agrees |
| 5 ESL of rs1, rs2 resisted | AL5 | 0/1000 guesses | agrees; but capture (A1) makes rs1/rs2 irrelevant |
| — | A1, A2, A4, **A5**, E, C | not in the log | added |
"""),
    md("""
# Phase 2 — Trying to break FSL-AKE-IoD

Each subsection runs the PoC against all four protocol columns. Every PoC either succeeds or reports exactly why it
fails.
"""),
    md("""
## 2.1 Replay — inside and outside ΔT, after resynchronisation, with clock skew, after an ES reboot
"""),
    code("show(A.replay_inside, A.replay_outside, A.replay_after_resync, A.replay_with_clock_skew, A.reboot_replay)"),
    md("""
**Output explanation.** BAKMM-IoD accepts an in-window replay (on_confirm). v1's cache blocks the plain replay, but
it keeps entries only until *receive time* + ΔT. When the drone's clock runs 1 s ahead (legal, because |skew| < ΔT),
the message is still fresh after the entry has expired. The replay is then accepted, and because the replay matches
v1's *old* record, the ES deletes the record the drone holds: **permanent lock-out**. The same happens after an ES
reboot empties the cache. v2 keeps entries until $T_1+\\Delta T$ (F2) and imposes a 2ΔT quiet period after a reboot.
"""),
    md("## 2.2 MITM / message modification, reflection, parallel-session interleaving"),
    code("show(A.modify_fields, A.reflection, A.interleave)"),
    md("""
**Output explanation.** Every field of both FSL messages is covered by V1 or V2, so each single-field change is
rejected. In BAKMM-IoD, **M5 is not covered by M4** (new flaw A5): the modified M5 is accepted and the drone is then
locked out. Reflection fails because MSG1 and MSG2 have different structures and keyed checks. Swapped MSG2s
between two parallel drones fail because MSG2 is bound to the drone's own K, N1 and T1.
"""),
    md("## 2.3 Drone impersonation and ES impersonation (no secrets)"),
    code("show(A.drone_impersonation, A.es_impersonation)"),
    md("**Output explanation.** Neither side can be impersonated without K (FSL) or MS/RID (BAKMM): recombined observed fields and random messages are all rejected."),
    md("## 2.4 Drone capture — KCI, past sessions (forward secrecy), future sessions, linkability of past TIDs"),
    code("show(A.kci_after_capture, A.capture_past_keys, A.capture_future_keys, A.capture_link_tids)"),
    md(r"""
**Output explanation.**
* **Forward secrecy holds** in FSL: the captured $K_n$ cannot be inverted to $K_{n-1}$, so 0/5 past keys are recovered.
* **KCI succeeds** in both protocols. With symmetric keys only, whoever holds the drone's key can impersonate the ES
  *to that drone*. This is inherent to the design and should be stated as a limitation rather than left unclaimed.
* **Future sessions** fall in both protocols: the adversary follows the key chain passively (no post-compromise
  security). The draft's Table 3 acknowledges this.
* **Linkability of past TIDs** in FSL is PARTIAL. After successful sessions nothing links. But if the drone's last
  attempt failed (MSG2 dropped), its stored TID equals the TID last seen on the air, which links that attempt.
"""),
    md("## 2.5 ES database — stolen without $X_{ES}$, and full ES compromise with $X_{ES}$ (quantified)"),
    code("show(A.stolen_db_without_X, A.es_compromise_with_X)"),
    md(r"""
**Output explanation.** Without $X_{ES}$ the masked table is useless. With $X_{ES}$ (3 drones × 5 sessions),
**3/15 past sessions** are exposed: exactly the last one of each drone, because the ES keeps the anchor key until the
drone's next session. All future sessions until re-keying are exposed as well. This matches the draft's "only the most
recent session key" claim. The ablation notebook shows that adding MSG3 (M6 off) removes even that single session.
"""),
    md("## 2.6 ESL / CK — reveal N1, N2 only; reveal SK_n only (does it give K_n?); reveal state mid-session; known-session-key"),
    code("show(A.esl_ephemerals_only, A.reveal_sk_get_k, A.reveal_state_mid_session, A.known_session_key)"),
    md(r"""
**Output explanation.** All four are resisted. Note that the FSL ESL claim is **vacuous**: $N_1, N_2$ are sent in the
clear, so ephemeral leakage reveals nothing new, and all secrecy rests on $K$. Revealing $SK_n$ does not give
$K_{n+1}=h(K_n\parallel SK_n)$ without $K_n$. Revealed keys do not help with other sessions.
"""),
    md("## 2.7 De-synchronisation — drop MSG2 once, repeatedly, reordered retries across the two records, eviction, two ES"),
    code("show(A.desync_drop_once, A.desync_drop_repeated, A.desync_reordered_retry, A.desync_candidate_eviction, A.cross_es)"),
    md(r"""
**Output explanation.**
* Single and repeated drops are handled by both FSL versions.
* **v1 breaks across its two records.** The drone retries (two fresh MSG1 on the same credentials). The adversary
  delivers the second first, so the drone completes with it, and then releases the first. v1 treats that as a message
  on the *old* record and deletes the *current* record, which is the one the drone holds. With six withheld retries the
  same happens. v2's candidate set (F3) and retry gap (F4) close both.
* A drone provisioned at **two ES** with the same credentials stops working at the second ES as soon as it rotates at
  the first (BAKMM-IoD too). Roaming needs per-ES credentials. This is a functional limitation, not an attack.
"""),
    md("## 2.8 DoS — cache flooding, TID lookup exhaustion, clock skew and ΔT edges"),
    code("show(A.dos_costs, A.delta_t_edges)"),
    md(r"""
**Output explanation.** An unknown TID costs the ES 0 hashes, and a known TID with garbage costs 2. Cache entries are
inserted only after a valid MAC, so forged messages cannot fill the cache. $|skew| = \Delta T$ is accepted and
$\Delta T+1$ rejected (inclusive bound). A drone whose clock drifts beyond ΔT is locked out until its clock is
corrected. That is inherent to timestamp freshness and applies to both protocols.
"""),
    md("## 2.9 Privileged insider at the RA; dynamic addition and revocation"),
    code("show(A.insider_ra, A.dynamic_add_default_enroll, A.revocation)"),
    md(r"""
**Output explanation.**
* **Insider (PARTIAL for all).** If the RA keeps $K_0$ and records *every* transcript, it derives all SKs (6/6). If it
  misses one transcript, the chain breaks (only the 2 earlier SKs). The RA must erase $K_i$, which is the same
  assumption BAKMM-IoD's Prop. 3 makes. Only a public-key exchange would remove it.
* **Dynamic addition in v1 is broken.** `enroll()` defaults to `dev="DE"`, so the first drone's session deletes the
  second drone's record (**F1**).
* **Revocation.** Deleting only the *current* record (v1) leaves the old record, and a drone whose MSG2 was dropped
  still authenticates. v2's `revoke(dev)` removes the anchor and all candidates.
"""),
    md(r"""
## 2.10 TID collision after truncating $h(\cdot)$ to 160 bits

Demo with 8-bit TIDs to force collisions, plus the analytic bound for 160 bits.
"""),
    code("""
import cost
display(show(A.tid_collision))
b = cost.tid_collision_bound(); print(f"160-bit bound: G = {b['pseudonyms']:.1e} pseudonyms -> P(collision) <= G^2 / 2^161 = {b['bound']:.2e}")
"""),
    md(r"""
**Output explanation.** v1 indexes records in a dict keyed by TID, so a collision overwrites another drone's record
(47/160 sessions fail with 8-bit TIDs). v2 keeps a list per identifier and tries each record's key, so collisions are
harmless (0/160). At 160 bits, even $10^6$ drones × $10^6$ sessions give $P\le1.4\times10^{-24}$.
"""),
    md("## 2.11 Anonymity — can a passive observer link two sessions of the same drone?"),
    code("""
display(show(A.anonymity_passive))
print(A.anonymity_passive(A.FSLv2Impl(F.without(retry_pseudonyms=3), "FSL-v2 + retry pseudonyms (w=3)")))
"""),
    md(r"""
**Output explanation.** Successful sessions are unlinkable in both protocols. But **every failed attempt makes the
retry reuse the same TID**: 4 linkable pairs in 12 sessions with one third of MSG2 dropped. An active adversary who drops
every MSG2 can therefore track a drone indefinitely. The draft's "an eavesdropper cannot link sessions" is an overclaim.
The optional extension `retry_pseudonyms = w` (the drone sends $h(TID\parallel j)$ on retry $j$) removes it for up to
$w$ retries, at a cost of $w$ extra hashes per session on the ES (7 → 10 for $w=3$).
"""),
    md("# ATTACK × PROTOCOL matrix"),
    code("""
M = A.matrix()
names = [i.name for i in IMPLS]
mat = pd.DataFrame([{**{"attack": row[names[0]].attack}, **{n: row[n].outcome for n in names},
                     "FSL-v2 reason": row["FSL-v2"].reason} for row in M.values()])
mat
"""),
    code("mat[names].apply(pd.Series.value_counts).fillna(0).astype(int)"),
    md(r"""
**Output explanation.** Against FSL-AKE-IoD **v1 as drafted, 9 of 32 attacks succeed**. Seven of them are
permanent lock-outs or bugs that v2 fixes; the other two (KCI and future keys after capture) are inherent.
**v2 leaves only** the rows that no symmetric-key-only protocol can resist (KCI after capture, future keys after
capture) plus PARTIAL rows: one past session exposed on full ES compromise, linkability of failed attempts and of the
last failed attempt after capture, the RA-insider assumption, clock drift beyond ΔT, and roaming between ground
stations. BAKMM-IoD fails every capture and database row, one-message de-sync,
and the M5 modification.
"""),
    md(r"""
# Phase 3 — Formal verification status

| Model | Purpose | Expected result | Status |
|---|---|---|---|
| `bakmm_auth.spdl`, `bakmm_key_mgmt.spdl`, `models/*.spdl` | existing BAKMM models | as in the paper (Fig. 5) | **NOT RUN** — Scyther not installed |
| `proposed/code/fslake_iod.spdl` | draft's FSL model | Secret/SKR/Alive/Weakagree Ok; the draft did not claim ES Niagree | **NOT RUN** |
| `fslake_auth.spdl`, `fslake_key_mgmt.spdl` | v2 DE–ES / ES–CS | DE claims Ok; ES Niagree → replay trace (cache not expressible) | **NOT RUN** |
| `bakmm_auth_compromise.spdl` | capture after session, XOR as encryption | **Secret SK Fail** | **NOT RUN** (Python equivalent A1 VERIFIED) |
| `bakmm_auth_compromise_xorfun.spdl` | same, XOR as uninterpreted function (paper style) | Secret SK **Ok = false negative** | **NOT RUN** |
| `fslake_auth_compromise.spdl` | capture after session, evolved key leaks | **Secret SK Ok** | **NOT RUN** (Python `capture_past_keys` VERIFIED) |
| `fslake_auth_compromise_control.spdl` | control: un-evolved key leaks | Secret SK Fail | **NOT RUN** |
| `proverif/bakmm_fs.pv`, `proverif/fslake_fs.pv` | phase-1 capture, `query attacker(secret)` | BAKMM: attacker true; FSL: not attacker | **NOT RUN** — ProVerif not installed |

Run everything with `SCYTHER=/path/to/scyther-linux bash scripts/run_formal.sh`. It writes `formal_results/*.txt`
and claim-table PNGs to `images/scyther_*.png`.

**Important modelling point.** The paper's Scyther model (Fig. 3/4), and every BAKMM `.spdl` in this repository,
declares `const xor: Function;`, an *uninterpreted* symbol with no cancellation law. The intruder can then never
remove a mask, so Scyther **cannot** find A1, however many runs it explores. The paper's "No attacks within bounds"
is therefore no evidence of capture resistance. `bakmm_auth_compromise.spdl` models masking as encryption keyed by
the mask, which is sound for this purpose.
"""),
    md(r"""
# Proof sketch (ROR model) for FSL-AKE-IoD v2

**Model.** A Real-or-Random game in the style of Abdalla–Fouque–Pointcheval. $h$ is a random oracle with output
length $\ell=256$ ($\ell_T=160$ for TIDs). $\mathcal{A}$ has $Execute$, $Send$, $Reveal$ (session key),
$Corrupt_{DE}$ (the drone's current $\{TID,K\}$), $Corrupt_{ES}$ (DB without $X_{ES}$) and one $Test$ query.
Freshness excludes: Reveal of the tested session or its partner; Corrupt of the tested drone *before* the tested
session completes (so forward secrecy covers corruption *after*); and Corrupt of $X_{ES}$ before the drone's next
session. Let $q_h$ be the number of hash queries, $q_s$ the number of Send queries and $q_e$ the number of Execute
queries.

**Game sequence.**
* $G_0$: the real protocol. $Adv = |2\Pr[Succ_0]-1|$.
* $G_1$: simulate $h$ with a table. Identical: $\Pr[Succ_1]=\Pr[Succ_0]$.
* $G_2$: abort on collisions of $h$ outputs, nonces or TIDs. $|\Pr[Succ_2]-\Pr[Succ_1]| \le \frac{q_h^2}{2^{\ell+1}} + \frac{(q_s+q_e)^2}{2^{161}}$.
* $G_3$: abort if $\mathcal{A}$ produces a valid $V_1$ or $V_2$ without querying $h$ on $K$. Forging a MAC-like tag
  without the key costs $\le q_s/2^{\ell}$. After this, entity authentication holds; with the cache (F2) and the
  quiet period, each accepted $MSG_1$ is fresh, which gives injectivity.
* $G_4$: replace $SK$ in the tested session by a random value. $\mathcal{A}$ notices only by querying
  $h(K_n\parallel N_1\parallel N_2\parallel T_1\parallel T_2\parallel TID)$ with the right $K_n$. Before the test
  session, $K_n$ is uniformly random given the view, because each $K_j=h(K_{j-1}\parallel SK_{j-1})$ is a fresh
  random-oracle output and $SK_{j-1}$ is hidden by $G_3$. After a later $Corrupt_{DE}$, $\mathcal{A}$ holds
  $K_{n+1}=h(K_n\parallel SK_n)$, which is independent of $K_n$ in the ROM. $Corrupt_{ES}$ without $X_{ES}$ gives
  $C=K\oplus h(X_{ES}\parallel TID)$, a one-time pad. $|\Pr[Succ_4]-\Pr[Succ_3]|\le q_h/2^{\ell}$, and $\Pr[Succ_4]=1/2$.

$$Adv^{ROR}_{\text{FSL-AKE}}(\mathcal{A}) \le \frac{q_h^2}{2^{\ell}} + \frac{(q_s+q_e)^2}{2^{160}} + \frac{2q_s+2q_h}{2^{\ell}}.$$

**What the proof does *not* give.** KCI (a corrupted drone key authenticates anything *to* that drone); security of
sessions after a corruption (no post-compromise security); availability. Those rows are confirmed empirically in the
matrix above. This is a sketch, not a machine-checked proof; the ProVerif query in `proverif/fslake_fs.pv` is the
automated counterpart (NOT RUN).
"""),
]

# ============================================================================ 3. ablation
ABL = [
    md(r"""
# FSL-AKE-IoD — Ablation Study

Does every design modification pay for itself? Each switch in `fslake.Config` is turned **off one at a time** and the
relevant attacks are re-run. A cell is *re-opened* when an attack that the full protocol (v2) resists succeeds, or
gets strictly worse, with the switch off.

| Switch | Modification |
|---|---|
| M1 | one-way key evolution $K\leftarrow h(K\parallel SK)$ |
| M2 | implicit TID update $TID\leftarrow h(TID\parallel SK)$ |
| M3 | dual record at the ES (v2: anchor + candidates) |
| M4 | replay cache $(TID,T_1,N_1)$ |
| M5 | masked verifier $C=K\oplus h(X_{ES}\parallel TID)$ |
| M6 | two-message flow (off = add $MSG_3=\{h(SK\parallel T_3),T_3\}$ as key confirmation) |
| F2–F4 | review fixes: cache expiry from $T_1$; candidate set; retry gap |
"""),
    code(SETUP + "\nimport ablation, attacks_fslake as A\nT = ablation.run()"),
    md("## MODIFICATION × ATTACK matrix"),
    code("""
atk = [a.__name__ for a in ablation.ATTACKS]
rows = []
for label, v in T.items():
    r = {"variant": label}
    for a in atk:
        res, worse = v["results"][a]
        r[res.attack] = ("RE-OPENED: " if worse else "") + res.outcome
    c = v["cost"]; r["hash DE/ES"] = f"{c['de']}/{c['es']}"; r["msgs/bits"] = f"{c['msgs']}/{c['bits']}"
    rows.append(r)
mat = pd.DataFrame(rows).set_index("variant")
mat.T
"""),
    code("pd.Series({k: (', '.join(v) if v else '— nothing —') for k, v in ablation.reopened(T).items()}, name='re-opened attacks').to_frame()"),
    md(r"""
**Output explanation.**

| Switch off | Re-opened attack | Reading |
|---|---|---|
| M1 | capture → past SKs (5/5) and past-TID linking | forward secrecy comes entirely from key evolution |
| M2 | passive linking of *all* sessions; capture links every past TID | the static pseudonym is sent on every run |
| M3 | one dropped MSG2 → permanent lock-out | a single record cannot absorb a lost message |
| M4 | in-window replay accepted (and replay with clock skew) | timestamps alone are not enough (same flaw as BAKMM-IoD A4) |
| M5 | stolen ES DB → drone impersonation | the plain key table is the verifier |
| **M6** | **nothing** | adding MSG3 re-opens no attack and **lowers** ES-compromise exposure from 3/15 to **0/15** past sessions (the ES can forget the old key on confirmation) at +288 bits and +1 hash per side. **M6 is a cost optimisation that trades away ES-side forward secrecy of the last session; it is not a security modification.** |
| F2 | replay with +1 s clock skew → lock-out | v1 bug |
| F3 | reordered retry and 6 withheld retries → lock-out | v1 bug |
| F4 | 6 withheld retries evict the drone's candidate | found while reviewing F3 |

So M1–M5 and F2–F4 are each necessary: removing any one re-opens a specific attack. **The claim that "every
modification is necessary" is false for M6**, which only buys cost.
"""),
    md("## Cost of each variant (instrumented)"),
    code("""
pd.DataFrame([dict(variant=k, DE=v['cost']['de'], ES=v['cost']['es'], messages=v['cost']['msgs'], bits=v['cost']['bits'])
              for k, v in T.items()]).set_index("variant")
"""),
    md("""
**Output explanation.** Most switches do not change the cost. M1/M2 off save one hash each on both sides (though with
M2 off the ES must try two records under the same TID, so its cost rises to 8). M5 off saves the ES two hashes. M6 off
costs one hash per side and 288 bits.
"""),
]

# ============================================================================ 4. performance
PERF = [
    md(r"""
# FSL-AKE-IoD — Performance Verification

Hash operations are counted by **instrumenting** $h(\cdot)$ during real runs, not by hand. Bits use the paper's field
sizes (ID/nonce 160, hash 256, timestamp 32). Milliseconds use the paper's Table 6/7 averages
($T_h$ = 0.055 ms server, 0.309 ms Raspberry Pi 3). Real SHA-256 timings are measured on this machine.
"""),
    code(SETUP + "\nimport cost, fslake as F"),
    md("## 1. Hash operations per entity (instrumented)"),
    code("""
rows = [cost.count_bakmm(), cost.count_bakmm("on_send"), cost.count_fsl_v1(), cost.count_fsl(),
        cost.count_fsl(F.without(M6_two_message=False), "FSL v2 + MSG3 (M6 off)"),
        cost.count_fsl(F.without(retry_pseudonyms=3), "FSL v2 + retry pseudonyms w=3")]
pd.DataFrame([{k: r[k] for k in ("scheme", "de", "es", "msgs", "bits", "per_msg")} for r in rows])
"""),
    code("print('BAKMM per step:', cost.count_bakmm()['de_steps'], cost.count_bakmm()['es_steps']); print(cost.count_bakmm_km())"),
    md(r"""
**Output explanation.** BAKMM-IoD: drone 3 (AKDDE1) + 5 (AKDDE3) = **8**, ES 7 (AKDDE2) + 1 (AKDDE4) = **8**. This
matches the paper's Table 8 ($8T_h$/$8T_h$), although the paper does not say how it counted.
FSL-AKE-IoD v1 and v2: **5/7**. The review fixes add no hash. The optional 3-message variant costs 6/8, and retry
pseudonyms cost the ES $w$ extra hashes.
"""),
    md("## 2. Communication cost"),
    code("""
b, f = cost.count_bakmm(), cost.count_fsl()
print(f"BAKMM-IoD : {' + '.join(map(str, b['per_msg']))} = {b['bits']} bits in {b['msgs']} messages "
      f"(M5 counted as 256 bits like the paper; {b['bits_actual']} if M5 is 160 bits)")
print(f"FSL-AKE-IoD: {' + '.join(map(str, f['per_msg']))} = {f['bits']} bits in {f['msgs']} messages")
print(f"saving: {100 * (1 - f['bits'] / b['bits']):.1f} %")
"""),
    md("**Output explanation.** 1792 → 1056 bits (−41.1 %) and 3 → 2 messages, as the draft claims. The paper's §7.2 total prints 1782, but its own terms sum to 1792."),
    md("## 3. Real timings on this machine"),
    code("""
t = cost.sha256_timing(100_000)
print(f"h() (5-part SHA-256): mean {t['h_mean_ms']*1e3:.3f} us, std {t['h_std_ms']*1e3:.3f} us, median {t['h_median_ms']*1e3:.3f} us  (n={t['runs']})")
print(f"raw hashlib, 64 B   : mean {t['raw_mean_ms']*1e3:.3f} us, std {t['raw_std_ms']*1e3:.3f} us, median {t['raw_median_ms']*1e3:.3f} us")
s = cost.session_timing(5000)
pd.DataFrame(s).T.map(lambda v: f"{v*1e3:.1f} us")
"""),
    md("""
**Output explanation.** A SHA-256 call costs a few microseconds in CPython. The large standard deviation comes from
OS scheduling outliers (the median is the robust figure). A full FSL-AKE-IoD session runs faster than a BAKMM-IoD
session on this machine, as the hash counts predict. These are PC numbers in Python; they are **not** comparable with
the paper's MIRACL/Raspberry Pi figures, which is why the comparison below uses the paper's $T_h$.
"""),
    md("## 4. Comparison with the paper's Table 8/9 schemes"),
    code("""
rows = cost.comparison_rows()
pd.DataFrame(rows)[["scheme", "drone_f", "drone_ms", "server_f", "server_ms", "msgs", "bits"]]
"""),
    code("""
import charts
paths = charts.main()
from IPython.display import Image, display
for p in paths: display(Image(filename=p, width=760))
"""),
    md("## 5. Is FSL-AKE-IoD strictly cheaper on both computation and communication?"),
    code("""
me, ties = cost.strictly_cheaper(rows)
for metric, lst in ties.items():
    print(f"{metric:10s}: FSL = {me[metric]}; schemes at least as cheap: {lst if lst else 'none'}")
"""),
    md(r"""
**Output explanation — answer: no, not on the server.**
* Drone: $5T_h$ = 1.545 ms, the lowest of all nine schemes.
* Communication: 1056 bits in 2 messages, the lowest bits and fewest messages.
* **Server: $7T_h$ = 0.385 ms is higher than Algarni & Jan ($6T_h$ = 0.33 ms)** and equal to Mishra et al. ($7T_h$,
  printed as 0.39 ms). It is lower only than BAKMM-IoD and the others. The draft's abstract says "cheaper … in both
  computation and communication"; that holds against BAKMM-IoD, not against every compared scheme.
* Counting convention: Table 8's figures for other schemes come from their own papers and may count only
  sender-side hashes. Our 5/7 includes every verification hash, so the comparison is, if anything, conservative for
  FSL-AKE-IoD.
"""),
    md("## 6. Storage and collision bound"),
    code("""
print("drone storage: BAKMM {TID, RID, TC, MS} =", 20 + 32 + 32 + 32, "bytes;  FSL {TID, K} =", 20 + 32, "bytes")
print("ES storage per drone (FSL v2): anchor + <= 4 candidates, each (TID 20 + C 32) bytes -> 52..260 bytes; steady state 104 bytes")
print(cost.tid_collision_bound())
"""),
    md("""
**Output explanation.** From the paper's field sizes we get 116 bytes for the BAKMM-IoD drone (TID 20 + RID 32 + TC 32
+ MS 32; RID and TC are hash outputs, and MS is taken as 256 bits). The draft's "about 136 bytes" cannot be reproduced
from the stated sizes and should be corrected or explained. In the steady state the FSL ES holds two records per drone,
matching the draft's "2 × 52 bytes"; the candidate list can briefly grow to five records.
"""),
]


def main():
    out = {
        "FSL-AKE-IoD-proposed_protocol.ipynb": PROTOCOL,
        "FSL-AKE-IoD-security_verification.ipynb": SEC,
        "FSL-AKE-IoD-ablation.ipynb": ABL,
        "FSL-AKE-IoD-performance.ipynb": PERF,
    }
    for name, cells in out.items():
        path = os.path.join(ROOT, name)
        nbf.write(notebook(cells), path)
        print("wrote", name)
        if "--no-exec" not in sys.argv:
            subprocess.run([sys.executable, "-m", "jupyter", "nbconvert", "--to", "notebook", "--execute",
                            "--inplace", "--ExecutePreprocessor.timeout=900", path], check=True, cwd=ROOT)


if __name__ == "__main__":
    main()
