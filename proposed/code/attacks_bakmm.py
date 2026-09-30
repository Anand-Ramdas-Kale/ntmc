"""Proof-of-concept attacks on BAKMM-IoD (Wazid et al., JSA 2025).

  Attack 1  Drone capture => all PAST (and future) session keys + TID chain (no forward secrecy,
            breaks Prop. 5 / ASFF8, ASFF10, ASFF13).
  Attack 2  Stolen ES verifier table => impersonate any drone and recover its session keys.
  Attack 3  De-synchronisation: delete one message => drone permanently locked out.
  Attack 4  Replay of MSG1 inside the Delta-T window is accepted (no nonce cache).

Run:  python3 attacks_bakmm.py
"""
import copy
from common import Clock, h, xor, rnd, AuthError, ID_BYTES
import bakmm_iod as B


def line(t):
    print("\n" + "=" * 78 + "\n" + t + "\n" + "=" * 78)


# ---------------------------------------------------------------- Attack 1
def attack_drone_capture(n_sessions=5):
    line("ATTACK 1: physical drone capture -> recover every past session key")
    clock = Clock()
    _, es, de = B.setup(clock)
    transcripts, true_keys = [], []
    for _ in range(n_sessions):                     # passive eavesdropping
        tr, sk_de, sk_es = B.run_session(de, es, clock)
        assert sk_de == sk_es
        transcripts.append(tr); true_keys.append(sk_de)
        clock.advance(60)

    # Drone is captured AFTER the sessions; power analysis dumps its memory.
    stolen = copy.deepcopy(de.mem)                  # {TID, RID, TC, MS}
    RID, MS = stolen["RID"], stolen["MS"]           # RID and MS never change

    recovered, tid_chain = [], []
    for tr in transcripts:
        m1, m2 = tr["MSG1"], tr["MSG2"]
        T1, T2 = m1["T1"], m2["T2"]
        A = xor(m1["M1"], h(RID, MS, T1))           # h(TC||rs1||MS||T1)
        Bv = xor(m2["M3"], h(RID, MS, T2))          # h(RID_ES||TC_ES||rs2||MS||T2)
        SK = h(A, Bv, T1, T2, RID, MS)
        recovered.append(SK)
        tid_chain.append((m1["TID"], xor(m2["M5"], h(A, RID, T2)[:ID_BYTES])))

    ok = all(a == b for a, b in zip(recovered, true_keys))
    for i, (sk, (old, new)) in enumerate(zip(recovered, tid_chain)):
        print(f"  session {i+1}: SK recovered = {sk.hex()[:24]}...  "
              f"match={sk == true_keys[i]}  TID {old.hex()[:8]} -> {new.hex()[:8]}")
    linked = all(tid_chain[i][1] == tid_chain[i + 1][0] for i in range(len(tid_chain) - 1))
    print(f"\n  RESULT: {sum(a == b for a, b in zip(recovered, true_keys))}/{n_sessions} past session keys recovered")
    print(f"  RESULT: pseudonym chain fully linked across sessions = {linked}  (untraceability broken)")
    # Future sessions too:
    tr, sk_de, _ = B.run_session(de, es, clock)
    A = xor(tr["MSG1"]["M1"], h(RID, MS, tr["MSG1"]["T1"]))
    Bv = xor(tr["MSG2"]["M3"], h(RID, MS, tr["MSG2"]["T2"]))
    fut = h(A, Bv, tr["MSG1"]["T1"], tr["MSG2"]["T2"], RID, MS)
    print(f"  RESULT: future session key also recovered = {fut == sk_de}")
    return ok and linked and fut == sk_de


# ---------------------------------------------------------------- Attack 2
def attack_stolen_verifier():
    line("ATTACK 2: stolen ES verifier table -> impersonate drone to ES")
    clock = Clock()
    _, es, de = B.setup(clock)
    B.run_session(de, es, clock)
    dump = copy.deepcopy(es.db)                     # {TID: {RID, MS}} stored in the clear
    TID, rec = next(iter(dump.items()))
    RID, MS = rec["RID"], rec["MS"]

    # Adversary builds a valid MSG1 without ever knowing TC_DE (it is never checked!)
    fake_TC = rnd(32)
    fake = B.Drone(dict(TID=TID, RID=RID, TC=fake_TC, MS=MS), clock)
    clock.advance()
    try:
        tr, sk_adv, sk_es = B.run_session(fake, es, clock)
        print(f"  ES accepted forged drone; shared SK = {sk_es.hex()[:24]}...  "
              f"adversary knows SK = {sk_adv == sk_es}")
        print("  NOTE: TC_DE was random garbage -> TC_DE contributes nothing to authentication.")
        return sk_adv == sk_es
    except AuthError as e:
        print("  rejected:", e)
        return False


# ---------------------------------------------------------------- Attack 3
def attack_desync():
    line("ATTACK 3: de-synchronisation (delete one message)")
    results = {}
    for policy, drop in (("on_confirm", "MSG3"), ("on_send", "MSG2")):
        clock = Clock()
        _, es, de = B.setup(clock, tid_update=policy)
        B.run_session(de, es, clock, drop=drop)     # adversary deletes one message
        clock.advance(60)
        fails = 0
        for _ in range(3):                          # legitimate retries
            try:
                B.run_session(de, es, clock); break
            except AuthError as e:
                fails += 1; reason = str(e); clock.advance(5)
        locked = fails == 3
        results[policy] = locked
        print(f"  ES updates TID '{policy}', adversary drops {drop}: "
              f"drone locked out = {locked}  ({reason if locked else 'recovered'})")
    return all(results.values())


# ---------------------------------------------------------------- Attack 4
def attack_replay_window():
    line("ATTACK 4: replay of MSG1 within Delta-T")
    clock = Clock()
    _, es, de = B.setup(clock, tid_update="on_confirm")
    msg1 = de.start()
    es.respond(msg1)                                 # genuine
    try:
        es.respond(copy.deepcopy(msg1))              # replay, same second
        print(f"  ES accepted the SAME MSG1 twice (accept log = {len(es.accepted)}); "
              "no nonce/timestamp cache -> injective agreement fails, ES state overwritten.")
        return True
    except AuthError as e:
        print("  replay rejected:", e); return False


if __name__ == "__main__":
    r = dict(capture=attack_drone_capture(), verifier=attack_stolen_verifier(),
             desync=attack_desync(), replay=attack_replay_window())
    line("SUMMARY (True = attack succeeded against BAKMM-IoD)")
    for k, v in r.items():
        print(f"  {k:10s}: {v}")
