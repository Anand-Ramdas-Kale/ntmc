"""Re-run the four BAKMM-IoD attacks against the proposed FSL-AKE-IoD.
Run:  python3 attacks_proposed.py
"""
import copy
from common import Clock, h, xor, rnd, AuthError, ID_BYTES
import proposed_fslake as P


def line(t):
    print("\n" + "=" * 78 + "\n" + t + "\n" + "=" * 78)


def capture(n=5):
    line("ATTACK 1 vs proposed: drone capture -> try to recover past session keys")
    clock = Clock(); _, es, de = P.setup(clock)
    trs, keys = [], []
    for _ in range(n):
        tr, a, b = P.run_session(de, es, clock); assert a == b
        trs.append(tr); keys.append(a); clock.advance(60)
    stolen = copy.deepcopy(de.mem)              # {TID_n, K_n}
    rec = 0
    for tr, true in zip(trs, keys):
        m1, m2 = tr["MSG1"], tr["MSG2"]
        guess = h(stolen["K"], m1["N1"], m2["N2"], m1["T1"], m2["T2"], m1["TID"])
        rec += guess == true
    linkable = stolen["TID"] in [t["MSG1"]["TID"] for t in trs]
    print(f"  past session keys recovered with captured K_n: {rec}/{n}")
    print(f"  captured TID appears in any past transcript (linkable): {linkable}")
    print("  (recovering K_{n-1} from K_n = h(K_{n-1}||SK_n) requires inverting SHA-256)")
    return rec == 0 and not linkable


def stolen_verifier():
    line("ATTACK 2 vs proposed: stolen ES table (without X_ES)")
    clock = Clock(); _, es, de = P.setup(clock)
    P.run_session(de, es, clock)
    dump = copy.deepcopy(es.db)
    TID, rec = [(t, r) for t, r in dump.items() if r["role"] == "cur"][0]
    fake = P.Drone(dict(TID=TID, K=rec["C"]), clock)   # best guess: use C as K
    clock.advance()
    try:
        P.run_session(fake, es, clock); print("  ES accepted forged drone"); return False
    except AuthError as e:
        print("  forged MSG1 rejected:", e); return True


def desync():
    line("ATTACK 3 vs proposed: adversary drops MSG2, then drone retries")
    clock = Clock(); _, es, de = P.setup(clock)
    P.run_session(de, es, clock, drop="MSG2")
    clock.advance(60)
    tr, a, b = P.run_session(de, es, clock)        # drone still on old TID/K
    ok1 = a == b
    clock.advance(60)
    tr, a, b = P.run_session(de, es, clock)        # and continues normally afterwards
    print(f"  recovery session succeeded: {ok1};  following session succeeded: {a == b}")
    return ok1 and a == b


def replay():
    line("ATTACK 4 vs proposed: replay MSG1 inside Delta-T")
    clock = Clock(); _, es, de = P.setup(clock)
    m1 = de.start(); es.respond(m1)
    try:
        es.respond(copy.deepcopy(m1)); print("  replay accepted"); return False
    except AuthError as e:
        print("  replay rejected:", e); return True


def correctness(n=1000):
    clock = Clock(); _, es, de = P.setup(clock)
    for _ in range(n):
        _, a, b = P.run_session(de, es, clock); assert a == b; clock.advance(10)
    print(f"\n  correctness: {n} consecutive sessions, keys agree every time")
    return True


if __name__ == "__main__":
    r = dict(capture=capture(), verifier=stolen_verifier(), desync=desync(),
             replay=replay(), correctness=correctness())
    line("SUMMARY (True = proposed protocol RESISTS the attack)")
    for k, v in r.items():
        print(f"  {k:12s}: {v}")
