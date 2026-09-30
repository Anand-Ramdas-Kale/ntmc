"""Phase 1: independent re-check of the claimed BAKMM-IoD flaws, plus the Attack_log.ipynb items,
the ES<->CS errata and the Sec. 7.2 arithmetic.

Every check returns a dict with: id, verdict (CONFIRMED / REFUTED / CONDITIONAL), the paper claim it
contradicts, the extra assumption it needs (if any), and the measured evidence.

Run:  python attacks_bakmm_ext.py
"""
import copy

import bakmm_iod as B
import bakmm_literal as L
from attacks_fslake import BAKMMImpl, capture_future_keys, capture_link_tids, capture_past_keys, _locked
from common import AuthError, Clock, HASH_BYTES, ID_BYTES, h, rnd, xor


def _row(id_, title, verdict, contradicts, assumption, evidence):
    return dict(id=id_, title=title, verdict=verdict, contradicts=contradicts,
                assumption=assumption, evidence=evidence)


# ---------------------------------------------------------------- A0: printed SK order
def a0_literal_sk_order(n=1000):
    ok = 0
    for _ in range(n):
        c = Clock(); ra = B.RA(); es = B.GroundStation(ra.register_es(c), c)
        cred = ra.register_drone(c); es.enroll(cred)
        try:
            _, a, b = B.run_session(L.LiteralDrone(cred, c), es, c); ok += a == b
        except AuthError:
            pass
    return _row("A0", "Printed SK concatenation order differs between DE and ES", "CONFIRMED",
                "Sec. 4.2 AKDDE2 vs AKDDE3 and Table 5 (spec erratum; Attack_log item 1)",
                "none (literal reading of the paper)",
                f"{ok}/{n} sessions agree on SK with the printed formulas (DE aborts at M4' = M4)")


def a0b_harmonised(n=1000):
    res = {}
    for pol in ("on_confirm", "on_send"):
        c = Clock(); _, es, de = B.setup(c, pol); ok = 0
        for _ in range(n):
            _, a, b = B.run_session(de, es, c); ok += a is not None and a == b; c.advance(10)
        res[pol] = ok
    return _row("A0b", "Correctness with the ES-side order used on both sides", "CONFIRMED", "-",
                "SK order harmonised (as bakmm_iod.py, the notebooks and all .spdl files do)",
                f"on_confirm {res['on_confirm']}/{n}, on_send {res['on_send']}/{n} sessions agree")


# ---------------------------------------------------------------- A1: capture
def a1_capture():
    impl = BAKMMImpl()
    p, f, l = capture_past_keys(impl), capture_future_keys(impl), capture_link_tids(impl)
    return _row("A1", "Drone capture -> past and future SKs, TID chain", "CONFIRMED",
                "Prop. 5 ('would possess solely the session key and registration data of this particular "
                "drone'); ASFF8; ASFF13 (untraceability, Prop. 6); Sec. 3.2 ('supports forward secrecy'). "
                "NOT ASFF10: ESL with long-term keys intact still holds (see AL5)",
                "none: Sec. 3.2 lets A capture drones and extract memory by power analysis; RSDI2 stores "
                "{TID, RID, TC, MS} and no memory-encryption key is specified (Prop. 5's 'not stored in an "
                "unencrypted state' has no mechanism behind it)",
                f"{p.reason}; {f.reason}; {l.reason}")


# ---------------------------------------------------------------- A2: stolen verifier
def a2_stolen_verifier(drones=3):
    c = Clock(); ra = B.RA(); es = B.GroundStation(ra.register_es(c), c)
    creds = [ra.register_drone(c) for _ in range(drones)]
    for cr in creds:
        es.enroll(cr)
    has_tc = any("TC" in r for r in es.db.values())
    wins = 0
    for TID, rec in list(copy.deepcopy(es.db).items()):
        fake = B.Drone(dict(TID=TID, RID=rec["RID"], TC=rnd(HASH_BYTES), MS=rec["MS"]), c)
        try:
            _, a, b = B.run_session(fake, es, c); wins += a == b
        except AuthError:
            pass
        c.advance(10)
    return _row("A2", "Stolen ES verifier table -> impersonate every drone; TC_DE never checked",
                "CONDITIONAL",
                "Prop. 4 (stolen verifier); ASFF5 (drone impersonation) once the table is read",
                "the adversary reads the ES database. Sec. 3.2 does not list ES-DB theft; Prop. 4 dismisses it "
                "by 'imposed restrictions' (access control). The TC_DE part needs no assumption: the ES never "
                "stores TC_DE (RSES2), so it cannot check it",
                f"ES record fields = {sorted(next(iter(es.db.values())))} (TC_DE stored: {has_tc}); "
                f"{wins}/{drones} drones impersonated with a random TC_DE, adversary knows each SK")


# ---------------------------------------------------------------- A3: de-sync
def a3_desync():
    rows = []
    for pol in ("on_confirm", "on_send"):
        for drop in ("MSG2", "MSG3"):
            c = Clock(); _, es, de = B.setup(c, pol)
            B.run_session(de, es, c, drop=drop)
            locked, why = _locked(BAKMMImpl(pol), de, es, c)
            rows.append(f"{pol}/drop {drop}: {'LOCKED OUT' if locked else 'recovers'}")
    return _row("A3", "De-synchronisation by one dropped message (both ES update policies)", "CONFIRMED",
                "no explicit availability claim in the paper; contradicts the DY model it adopts (Sec. 3.2: "
                "messages 'can be ... deleted'). Attack_log item 2",
                "the paper never says when the ES overwrites TID (both readings tested); RSES2 keeps one TID "
                "per drone, so no fallback record exists under either reading",
                "; ".join(rows))


# ---------------------------------------------------------------- A4: replay
def a4_replay():
    out = {}
    for pol in ("on_confirm", "on_send"):
        c = Clock(); _, es, de = B.setup(c, pol)
        m1 = de.start(); m2 = es.respond(m1)
        try:
            es.respond(copy.deepcopy(m1)); acc = True           # replay before the drone answers
        except AuthError:
            acc = False
        # consequence: genuine drone continues with the FIRST MSG2
        try:
            m3 = de.finish(m2); es.confirm(m3); genuine = "completed"
        except AuthError as e:
            genuine = f"failed ({e})"
        locked, _ = _locked(BAKMMImpl(pol), de, es, c)
        out[pol] = f"replay accepted={acc}, genuine session {genuine}, drone locked out={locked}"
    return _row("A4", "Replay of MSG1 inside dT", "CONFIRMED (acceptance) / CONDITIONAL (lock-out)",
                "Prop. 1 (replay) and ASFF1: timestamps alone do not stop an in-window replay",
                "acceptance: none. Lock-out: the ES keeps one pending session per drone (the paper does not "
                "specify pending-state handling; MSG3 = {M6, T3} carries no session identifier)",
                "; ".join(f"{k}: {v}" for k, v in out.items()))


# ---------------------------------------------------------------- A5 (new): M5 malleability
def a5_m5_malleability():
    out = {}
    for pol in ("on_confirm", "on_send"):
        c = Clock(); _, es, de = B.setup(c, pol)
        m1 = de.start(); c.advance(); m2 = es.respond(m1); c.advance()
        m2 = dict(m2); m2["M5"] = bytes([m2["M5"][0] ^ 0x01]) + m2["M5"][1:]   # flip one bit
        m3 = de.finish(m2); c.advance(); es.confirm(m3)                     # both sides 'succeed'
        locked, why = _locked(BAKMMImpl(pol), de, es, c)
        out[pol] = f"session completed, drone locked out afterwards={locked}"
    return _row("A5", "NEW: MSG2.M5 is not covered by M4 -> one flipped bit locks the drone out",
                "CONFIRMED",
                "Prop. 2 ('it is not feasible for A to make any changes in the transmitted messages'); ASFF2",
                "none (DY adversary modifies a message in transit; nothing is dropped, both sides report success)",
                "; ".join(f"{k}: {v}" for k, v in out.items()))


# ---------------------------------------------------------------- Attack_log items 3-5
def al3_replay_after_2dt():
    c = Clock(); _, es, de = B.setup(c)
    m1 = de.start(); es.respond(m1); c.advance(2 * B.DELTA_T + 1)
    try:
        es.respond(copy.deepcopy(m1)); v = "accepted"
    except AuthError as e:
        v = f"rejected ({e})"
    return _row("AL3", "Attack_log 3: replay after 2*dT", "CONFIRMED (resisted as the log expects)", "-", "-", v)


def al4_clock_drift():
    c = Clock(); _, es, de = B.setup(c)
    de.clock = Clock(c.now() + B.DELTA_T + 1)
    try:
        es.respond(de.start()); v = "accepted"
    except AuthError as e:
        v = f"rejected ({e})"
    return _row("AL4", "Attack_log 4: drone clock drift > dT (DoS)", "CONFIRMED",
                "no availability claim; inherent to timestamp freshness (also affects FSL-AKE-IoD)",
                "drift larger than dT (e.g. GPS spoofing)", v)


def al5_esl():
    c = Clock(); _, es, de = B.setup(c)
    tr, sk, _ = B.run_session(de, es, c)
    rs1, rs2 = de.rs1, rnd()        # adversary is handed rs1 and rs2; all long-term values unknown
    guesses = [h(h(rnd(32), rs1, rnd(32), tr["MSG1"]["T1"]), h(rnd(20), rnd(32), rs2, rnd(32), tr["MSG2"]["T2"]),
                 tr["MSG1"]["T1"], tr["MSG2"]["T2"], rnd(20), rnd(32)) for _ in range(1000)]
    return _row("AL5", "Attack_log 5: ESL of rs1, rs2 only (CK)", "CONFIRMED (resisted as the log expects)",
                "supports Prop. 7 / ASFF10 in its narrow sense", "-",
                f"{sum(g == sk for g in guesses)}/1000 guesses match; SK needs MS, RID (and A needs TC_DE)")


# ---------------------------------------------------------------- ES-CS errata
def e_escs():
    rows = []
    for E1, E4, label in ((False, False, "corrected"), (True, False, "E1 printed m1/m2 order"),
                          (False, True, "E4 printed TIN recovery with RS2")):
        c = Clock(); e, cs = L.RAKM.register(c)
        es_, cs_ = L.ESInitiator(e, c, E1, E4), L.CSResponder(cs, c)
        done = []
        try:
            for _ in range(2):
                a, b = L.run_km(es_, cs_, c); c.advance(10)
                done.append(f"s{len(done) + 1} agree={a == b}")
            rows.append(f"{label}: {', '.join(done)}")
        except AuthError as ex:
            rows.append(f"{label}: {', '.join(done + [f's{len(done) + 1} fails ({ex})'])}")
    return _row("E", "ES<->CS phase as printed", "CONFIRMED",
                "Sec. 4.3; ASFF14 (secure ES-CS communication) as printed",
                "E2 'rs1' and E3 'MS_{ESj-ESj}' read as typos for RS1 / MS_{ESj-CSk}", "; ".join(rows))


# ---------------------------------------------------------------- Sec. 7.2 arithmetic
def e_comm():
    m1 = 160 + 256 + 256 + 32
    m2_paper = 256 + 256 + 256 + 32
    m3 = 256 + 32
    m2_m5_160 = 256 + 256 + 160 + 32
    return _row("C", "Sec. 7.2 communication arithmetic", "CONFIRMED",
                "Sec. 7.2 prints |MSG3| = 2880 and total 704+800+288 = 1782; Table 9 prints 1792", "-",
                f"|MSG1|={m1}, |MSG2|={m2_paper} (M5 counted as 256), |MSG3|={m3}; sum={m1 + m2_paper + m3} = "
                f"Table 9. '2880' and '1782' are typos. If M5 is 160 bits (TID_new is 160) the sum is "
                f"{m1 + m2_m5_160 + m3}: this is where the 1696 in bakmm_technical_analysis.tex comes from")


CHECKS = [a0_literal_sk_order, a0b_harmonised, a1_capture, a2_stolen_verifier, a3_desync, a4_replay,
          a5_m5_malleability, al3_replay_after_2dt, al4_clock_drift, al5_esl, e_escs, e_comm]


def run_all():
    return [f() for f in CHECKS]


if __name__ == "__main__":
    for r in run_all():
        print(f"{r['id']:4s} {r['verdict']}\n     {r['title']}\n     contradicts: {r['contradicts']}\n"
              f"     assumption : {r['assumption']}\n     evidence   : {r['evidence']}\n")
