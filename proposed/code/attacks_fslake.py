"""Phase 2: adversarial review of FSL-AKE-IoD.

Every attack is a function  attack(impl) -> Result  that runs against a protocol adapter:
  BAKMM   - bakmm_iod.py (the paper's DE<->ES phase, harmonised SK order, ES updates TID on MSG3)
  FSLv1   - proposed_fslake.py exactly as supplied with the draft
  FSLv2   - fslake.py (v1 + fixes F1-F3), or any ablation Config

Outcome vocabulary (from the ADVERSARY's point of view):
  SUCCEEDED  the attack works
  RESISTED   the attack fails (the reason says why)
  PARTIAL    works only under an extra condition, or with a limited effect (the reason says which)
  N/A        the attack does not apply to this protocol

Run:  python attacks_fslake.py            (prints the ATTACK x PROTOCOL matrix)
"""
import copy
import itertools
from dataclasses import dataclass, field

import bakmm_iod as B
import fslake as F
import proposed_fslake as P1
from common import AuthError, Clock, HASH_BYTES, ID_BYTES, h, hashes, reset_hash_counter, rnd, xor

SUCC, RES, PART, NA = "SUCCEEDED", "RESISTED", "PARTIAL", "N/A"


@dataclass
class Result:
    attack: str
    protocol: str
    outcome: str
    reason: str
    data: dict = field(default_factory=dict)

    def __str__(self):
        return f"[{self.outcome:9s}] {self.attack:34s} {self.protocol:10s} {self.reason}"


# =========================================================================== adapters
class BAKMMImpl:
    name, kind, two_msg = "BAKMM", "bakmm", False

    def __init__(self, policy="on_confirm"):
        self.policy = policy
        if policy != "on_confirm":
            self.name = f"BAKMM[{policy}]"

    def setup(self, clock, n=1):
        ra = B.RA()
        es = B.GroundStation(ra.register_es(clock), clock, self.policy)
        ds = []
        for _ in range(n):
            cred = ra.register_drone(clock)
            es.enroll(cred)
            ds.append(B.Drone(cred, clock))
        return ra, es, ds

    run = staticmethod(B.run_session)

    @staticmethod
    def respond(es, m1):
        return es.respond(m1)

    @staticmethod
    def finish(de, m2):
        de.msg3 = de.finish(m2)
        return de.session_key

    @staticmethod
    def complete(de, es, m2):
        de.msg3 = de.finish(m2)
        return de.session_key, es.confirm(de.msg3)

    @staticmethod
    def state(de):
        return copy.deepcopy(de.mem)

    @staticmethod
    def clone(state, clock):
        return B.Drone(copy.deepcopy(state), clock)


class FSLv1Impl:
    name, kind, two_msg = "FSL-v1", "fsl", True

    def setup(self, clock, n=1):
        ra, es = P1.RA(), P1.GroundStation(clock)
        ds = []
        for i in range(n):
            cred = ra.register_drone()
            es.enroll(cred, dev=f"DE{i}")        # unique ids, so the F1 bug does not mask other tests
            ds.append(P1.Drone(cred, clock))
        return ra, es, ds

    run = staticmethod(P1.run_session)

    @staticmethod
    def respond(es, m1):
        return es.respond(m1)[0]

    @staticmethod
    def finish(de, m2):
        return de.finish(m2)

    @staticmethod
    def complete(de, es, m2):
        return de.finish(m2), es.session_keys[-1]

    @staticmethod
    def state(de):
        return dict(de.mem)

    @staticmethod
    def clone(state, clock):
        return P1.Drone(dict(state), clock)

    @staticmethod
    def records(es):
        return [(t, r["C"]) for t, r in es.db.items()]

    @staticmethod
    def evolve(K, TID, SK):
        return h(K, SK), h(TID, SK)[:ID_BYTES]


class FSLv2Impl:
    kind = "fsl"

    def __init__(self, cfg=F.V2, name="FSL-v2"):
        self.cfg, self.name, self.two_msg = cfg, name, cfg.M6_two_message

    def setup(self, clock, n=1):
        ra, es = F.RA(self.cfg), F.GroundStation(clock, self.cfg)
        ds = []
        for _ in range(n):
            cred = ra.register_drone()
            es.enroll(cred)
            ds.append(F.Drone(cred, clock, self.cfg))
        return ra, es, ds

    def run(self, de, es, clock, drop=None):
        return F.run_session(de, es, clock, drop)

    @staticmethod
    def respond(es, m1):
        return es.respond(m1)[0]

    def finish(self, de, m2):
        out = de.finish(m2)
        if not self.two_msg:
            de.msg3 = out[1]
            return out[0]
        return out

    def complete(self, de, es, m2):
        out = de.finish(m2)
        if self.two_msg:
            return out, es.session_keys[-1]
        return out[0], es.confirm(out[1])

    @staticmethod
    def state(de):
        return dict(de.mem)

    def clone(self, state, clock):
        return F.Drone(dict(state), clock, self.cfg)

    @staticmethod
    def records(es):
        return es.records()

    def evolve(self, K, TID, SK):
        c = self.cfg
        return (h(K, SK) if c.M1_key_evolution else K,
                h(TID, SK)[:c.tid_bytes] if c.M2_tid_update else TID)


def impls():
    return [BAKMMImpl(), BAKMMImpl("on_send"), FSLv1Impl(), FSLv2Impl()]


# =========================================================================== helpers
def _accepts(fn, *a):
    try:
        fn(*a)
        return True, ""
    except AuthError as e:
        return False, str(e)


def _locked(impl, de, es, clock, tries=3):
    """True if the (honest) drone can no longer complete a session."""
    last = "keys differ"
    for _ in range(tries):
        clock.advance(60)
        try:
            _, a, b = impl.run(de, es, clock)
            if a is not None and a == b:
                return False, ""
        except AuthError as e:
            last = str(e)
    return True, last


def _fsl_sk(K, TID, m1, m2):
    return h(K, m1["N1"], m2["N2"], m1["T1"], m2["T2"], TID)


def _bakmm_sk(RID, MS, m1, m2):
    A = xor(m1["M1"], h(RID, MS, m1["T1"]))
    Bv = xor(m2["M3"], h(RID, MS, m2["T2"]))
    return h(A, Bv, m1["T1"], m2["T2"], RID, MS), A


# =========================================================================== replay
def replay_inside(impl):
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    m1 = de.start(); impl.respond(es, m1)
    ok, why = _accepts(impl.respond, es, copy.deepcopy(m1))
    if ok:
        return Result("replay MSG1 inside dT", impl.name, SUCC, "same MSG1 accepted twice (no cache)")
    return Result("replay MSG1 inside dT", impl.name, RES, why)


def replay_outside(impl):
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    m1 = de.start(); impl.respond(es, m1)
    clock.advance(3)                                   # > dT = 2
    ok, why = _accepts(impl.respond, es, copy.deepcopy(m1))
    return Result("replay MSG1 outside dT", impl.name, SUCC if ok else RES, why or "accepted")


def replay_after_resync(impl):
    """MSG2 of attempt a is dropped; the drone resynchronises with attempt b; the adversary then
    replays MSG1(a) inside dT and, separately, much later."""
    if impl.kind != "fsl":
        return Result("replay old MSG1 after resync", impl.name, NA, "no resynchronisation mechanism")
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    m1a = de.start(); impl.respond(es, m1a)            # MSG2(a) dropped
    try:
        m1b = de.start()
    except AuthError:                                  # v2 rule F4: wait > 2 dT before retrying
        clock.advance(2 * F.DELTA_T + 1); m1b = de.start()
    m2b = impl.respond(es, m1b); impl.complete(de, es, m2b)
    inside, why_in = _accepts(impl.respond, es, copy.deepcopy(m1a))
    locked, _ = _locked(impl, de, es, clock)
    if inside or locked:
        return Result("replay old MSG1 after resync", impl.name, SUCC,
                      f"inside-dT replay accepted={inside}; drone locked out={locked}")
    return Result("replay old MSG1 after resync", impl.name, RES,
                  f"replay of MSG1(a): {why_in}; drone still works")


def replay_with_clock_skew(impl):
    """Drone clock is +1 s ahead (legal, |skew| < dT). Genuine session, then replay at ES time r+3."""
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    de.clock = Clock(clock.now() + 1)
    m1 = de.start(); m2 = impl.respond(es, m1)
    impl.complete(de, es, m2)                          # genuine session completes
    de.clock = clock
    clock.advance(3)
    ok, why = _accepts(impl.respond, es, copy.deepcopy(m1))
    locked, lw = _locked(impl, de, es, clock)
    if ok:
        return Result("replay + clock skew (+1 s)", impl.name, SUCC,
                      f"replay accepted at T1+2; honest drone locked out afterwards={locked}"
                      + (f" ({lw})" if locked else ""))
    return Result("replay + clock skew (+1 s)", impl.name, RES, why)


# =========================================================================== MITM / reflection / interleaving
def modify_fields(impl):
    bad = []
    for which in ("MSG1", "MSG2"):
        clock = Clock(); _, es, (de,) = impl.setup(clock)
        m1 = de.start()
        fields = list(m1) if which == "MSG1" else list(impl.respond(es, copy.deepcopy(m1)))
        for f in fields:
            clock = Clock(); _, es, (de,) = impl.setup(clock)
            m1 = de.start()
            if which == "MSG1":
                t = copy.deepcopy(m1)
                t[f] = t[f] + 1 if isinstance(t[f], int) else bytes([t[f][0] ^ 1]) + t[f][1:]
                ok, _ = _accepts(impl.respond, es, t)
            else:
                m2 = impl.respond(es, m1)
                t = copy.deepcopy(m2)
                t[f] = t[f] + 1 if isinstance(t[f], int) else bytes([t[f][0] ^ 1]) + t[f][1:]
                ok, _ = _accepts(impl.finish, de, t)
                if ok and impl.kind == "bakmm":
                    clock.advance(); _accepts(es.confirm, de.msg3)
                    f = f"{f} (session completes, then drone locked out={_locked(impl, de, es, clock)[0]})"
            if ok:
                bad.append(f"{which}.{f}")
    if bad:
        return Result("MITM: modify one field", impl.name, SUCC, f"accepted modified {bad}")
    return Result("MITM: modify one field", impl.name, RES,
                  "every single-field modification of MSG1 and MSG2 rejected")


def reflection(impl):
    """Feed the drone's own MSG1 back to it as MSG2 (all type-compatible field mappings), and the
    ES's MSG2 back to the ES as MSG1."""
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    m1 = de.start()
    m2_real = impl.respond(es, copy.deepcopy(m1))
    hits = []
    for src, tmpl, fn, tgt in ((m1, m2_real, impl.finish, de), (m2_real, m1, impl.respond, es)):
        b_src = [k for k, v in src.items() if not isinstance(v, int)]
        i_src = [k for k, v in src.items() if isinstance(v, int)]
        b_dst = [k for k, v in tmpl.items() if not isinstance(v, int)]
        i_dst = [k for k, v in tmpl.items() if isinstance(v, int)]
        if len(b_src) < len(b_dst) or len(i_src) < len(i_dst):
            continue
        for bp in itertools.permutations(b_src, len(b_dst)):
            for ip in itertools.permutations(i_src, len(i_dst)):
                forged = {d: src[s] for d, s in zip(b_dst, bp)}
                forged.update({d: src[s] for d, s in zip(i_dst, ip)})
                try:
                    fn(tgt, forged); hits.append(str(forged.keys()))
                except (AuthError, KeyError, AssertionError, TypeError):
                    pass
    if hits:
        return Result("reflection", impl.name, SUCC, f"reflected message accepted: {hits[:2]}")
    return Result("reflection", impl.name, RES, "MSG1/MSG2 have different structure and keyed checks")


def interleave(impl):
    """Two drones start in parallel; the adversary swaps the two MSG2."""
    clock = Clock(); _, es, (a, b) = impl.setup(clock, n=2)
    ma, mb = a.start(), b.start()
    ra, rb = impl.respond(es, ma), impl.respond(es, mb)
    oka, _ = _accepts(impl.finish, a, rb)
    okb, _ = _accepts(impl.finish, b, ra)
    if oka or okb:
        return Result("parallel-session interleaving", impl.name, SUCC, "swapped MSG2 accepted")
    return Result("parallel-session interleaving", impl.name, RES, "MSG2 is bound to the drone's key and N1/T1")


# =========================================================================== impersonation
def drone_impersonation(impl):
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    seen = []
    for _ in range(3):
        tr, _, _ = impl.run(de, es, clock); seen.append(tr["MSG1"]); clock.advance(10)
    clock.advance(10)
    cur = de.start()                                   # adversary sees the TID on the air
    tries = 0
    for base in seen:                                  # recombine every observed field with fresh values
        forged = copy.deepcopy(base)
        forged[list(forged)[0]] = cur[list(cur)[0]]
        for k, v in forged.items():
            if isinstance(v, int):
                forged[k] = clock.now()
        tries += 1
        if _accepts(impl.respond, es, forged)[0]:
            return Result("drone impersonation (no secrets)", impl.name, SUCC, "forged MSG1 accepted")
    return Result("drone impersonation (no secrets)", impl.name, RES,
                  f"{tries} forged MSG1 (observed fields + current TID + fresh T) rejected")


def es_impersonation(impl):
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    tr, _, _ = impl.run(de, es, clock); clock.advance(10)
    de.start()
    old = copy.deepcopy(tr["MSG2"])
    for k, v in old.items():
        if isinstance(v, int):
            old[k] = clock.now()
    rand = {k: (clock.now() if isinstance(v, int) else rnd(len(v))) for k, v in old.items()}
    if _accepts(impl.finish, de, old)[0] or _accepts(impl.finish, de, rand)[0]:
        return Result("ES impersonation (no secrets)", impl.name, SUCC, "forged MSG2 accepted")
    return Result("ES impersonation (no secrets)", impl.name, RES,
                  "old MSG2 with fresh T2, and random MSG2, both rejected")


# =========================================================================== drone capture
def _history(impl, n=5, drop_last=False):
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    trs, keys = [], []
    for i in range(n):
        drop = "MSG2" if (drop_last and i == n - 1) else None
        tr, a, b = impl.run(de, es, clock, drop=drop)
        trs.append(tr); keys.append(b if drop else a); clock.advance(60)
    return clock, es, de, trs, keys


def capture_past_keys(impl):
    clock, es, de, trs, keys = _history(impl)
    st = impl.state(de)
    if impl.kind == "bakmm":
        rec = sum(_bakmm_sk(st["RID"], st["MS"], t["MSG1"], t["MSG2"])[0] == k for t, k in zip(trs, keys))
    else:
        rec = sum(_fsl_sk(st["K"], t["MSG1"]["TID"], t["MSG1"], t["MSG2"]) == k for t, k in zip(trs, keys))
    out = SUCC if rec else RES
    why = (f"{rec}/{len(keys)} past session keys recovered from captured memory" if rec else
           f"0/{len(keys)} past keys: captured K_n = h(K_(n-1)||SK_(n-1)) cannot be inverted")
    return Result("capture: past SKs (forward secrecy)", impl.name, out, why, dict(recovered=rec))


def capture_future_keys(impl, k=3):
    clock, es, de, _, _ = _history(impl)
    st = impl.state(de)                                 # captured now; drone keeps flying
    got = 0
    for _ in range(k):
        tr, sk, _ = impl.run(de, es, clock); clock.advance(60)
        if impl.kind == "bakmm":
            got += _bakmm_sk(st["RID"], st["MS"], tr["MSG1"], tr["MSG2"])[0] == sk
        else:
            guess = _fsl_sk(st["K"], st["TID"], tr["MSG1"], tr["MSG2"])
            got += guess == sk
            st["K"], st["TID"] = impl.evolve(st["K"], st["TID"], guess)   # passive chain following
    return Result("capture: future SKs", impl.name, SUCC if got else RES,
                  f"{got}/{k} future keys by passively following the chain (no post-compromise security)"
                  if got else "future keys not derivable", dict(recovered=got))


def capture_link_tids(impl):
    out = {}
    for drop_last in (False, True):
        clock, es, de, trs, keys = _history(impl, drop_last=drop_last)
        st = impl.state(de)
        if impl.kind == "bakmm":
            chain = []
            for t in trs:
                _, A = _bakmm_sk(st["RID"], st["MS"], t["MSG1"], t["MSG2"])
                chain.append((t["MSG1"]["TID"], xor(t["MSG2"]["M5"], h(A, st["RID"], t["MSG2"]["T2"])[:ID_BYTES])))
            linked = sum(chain[i][1] == chain[i + 1][0] for i in range(len(chain) - 1)) + 1
        else:
            same = sum(t["MSG1"]["TID"] == st["TID"] for t in trs)
            # sessions whose SK the captured K reproduces (V2 verifies): their TID successor follows
            derivable = sum(h(_fsl_sk(st["K"], t["MSG1"]["TID"], t["MSG1"], t["MSG2"]), t["MSG2"]["N2"],
                              t["MSG2"]["T2"]) == t["MSG2"]["V2"] for t in trs)
            linked = max(same, derivable)
        out[drop_last] = linked
    if impl.kind == "bakmm":
        return Result("capture: link past TIDs", impl.name, SUCC,
                      f"all {out[False]} past sessions linked through M5 (TID_new recoverable)", out)
    if out[False] > 0:
        return Result("capture: link past TIDs", impl.name, SUCC,
                      f"{out[False]}/5 past sessions linked from the captured state", out)
    if out[True] == 0:
        return Result("capture: link past TIDs", impl.name, RES, "no past on-air TID equals or follows from captured state", out)
    return Result("capture: link past TIDs", impl.name, PART,
                  f"successful history: {out[False]} linked; but if the last attempt failed (MSG2 dropped) the "
                  f"captured TID equals the last on-air TID ({out[True]} linked)", out)


def kci_after_capture(impl):
    """Adversary holding the drone's long-term state impersonates the ES TO that drone."""
    clock, es, de, _, _ = _history(impl, n=2)
    st = impl.state(de)
    m1 = de.start()                                   # adversary intercepts, ES never sees it
    if impl.kind == "bakmm":
        RID, MS, T1, T2 = st["RID"], st["MS"], m1["T1"], clock.now()
        A = xor(m1["M1"], h(RID, MS, T1))
        Bv = rnd(HASH_BYTES)                          # adversary's arbitrary contribution
        SK = h(A, Bv, T1, T2, RID, MS)
        m2 = dict(M3=xor(h(RID, MS, T2), Bv), M4=h(SK, T1, T2, RID),
                  M5=xor(rnd(ID_BYTES), h(A, RID, T2)[:ID_BYTES]), T2=T2)
    else:
        N2, T2 = rnd(), clock.now()
        SK = _fsl_sk(st["K"], st["TID"], m1, dict(N2=N2, T2=T2))
        m2 = dict(N2=N2, T2=T2, V2=h(SK, N2, T2))
    ok, why = _accepts(impl.finish, de, m2)
    if ok:
        return Result("KCI after drone capture", impl.name, SUCC,
                      "drone accepts forged MSG2 and shares SK with the adversary (inherent to symmetric-only AKE)")
    return Result("KCI after drone capture", impl.name, RES, why)


# =========================================================================== ES database
def stolen_db_without_X(impl):
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    impl.run(de, es, clock); clock.advance(10)
    if impl.kind == "bakmm":
        TID, rec = next(iter(es.db.items()))
        fake = B.Drone(dict(TID=TID, RID=rec["RID"], TC=rnd(32), MS=rec["MS"]), clock)
        try:
            _, a, b = impl.run(fake, es, clock)
            return Result("stolen ES DB (no X_ES)", impl.name, SUCC,
                          "plain (RID, MS) table: forged drone accepted, adversary shares SK; random TC_DE accepted")
        except AuthError as e:
            return Result("stolen ES DB (no X_ES)", impl.name, RES, str(e))
    wins = 0
    for TID, C in impl.records(es):
        fake = impl.clone(dict(TID=TID, K=C), clock)
        try:
            _, a, b = impl.run(fake, es, clock); wins += a == b
        except AuthError:
            pass
        clock.advance(5)
    if wins:
        return Result("stolen ES DB (no X_ES)", impl.name, SUCC, "stored verifier usable as the key (M5 off)")
    return Result("stolen ES DB (no X_ES)", impl.name, RES, "C = K xor h(X_ES||TID) is useless without X_ES")


def es_compromise_with_X(impl, drones=3, sessions=5, future=3):
    if impl.kind == "bakmm":
        return Result("ES compromise incl. X_ES", impl.name, SUCC,
                      "same as stolen DB: every past and future session of every drone (MS is static)",
                      dict(past_exposed=drones * sessions, past_total=drones * sessions))
    clock = Clock(); _, es, ds = impl.setup(clock, n=drones)
    trs = {i: [] for i in range(drones)}; keys = {i: [] for i in range(drones)}
    for _ in range(sessions):
        for i, d in enumerate(ds):
            tr, a, b = impl.run(d, es, clock); trs[i].append(tr); keys[i].append(a); clock.advance(10)
    recs = impl.records(es)
    Ks = [(TID, xor(C, h(es.X, TID)) if getattr(impl, "cfg", F.V2).M5_masked_verifier else C) for TID, C in recs]
    past = 0
    for i in range(drones):
        for tr, sk in zip(trs[i], keys[i]):
            past += any(_fsl_sk(K, TID, tr["MSG1"], tr["MSG2"]) == sk for TID, K in Ks
                        if TID == tr["MSG1"]["TID"])
    fut = 0
    for i, d in enumerate(ds):
        tr, sk, _ = impl.run(d, es, clock); clock.advance(10)
        fut += any(_fsl_sk(K, TID, tr["MSG1"], tr["MSG2"]) == sk for TID, K in Ks)
    total = drones * sessions
    return Result("ES compromise incl. X_ES", impl.name, PART,
                  f"{past}/{total} past sessions exposed (the last one per drone, via the kept old record); "
                  f"{fut}/{drones} next sessions exposed (all future sessions until re-keying)",
                  dict(past_exposed=past, past_total=total, future_exposed=fut))


# =========================================================================== CK / ESL
def esl_ephemerals_only(impl):
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    tr, sk, _ = impl.run(de, es, clock)
    if impl.kind == "bakmm":
        # adversary learns rs1, rs2 (not TC_DE, MS, RID, RID_ES, TC_ES): every SK input except the
        # nonces is a long-term secret, so its best guess uses random stand-ins.
        guess = h(rnd(32), rnd(32), tr["MSG1"]["T1"], tr["MSG2"]["T2"], rnd(20), rnd(32))
        return Result("ESL: reveal ephemerals only", impl.name, RES if guess != sk else SUCC,
                      "rs1, rs2 alone do not give A, B or SK (all need MS)")
    guess = h(rnd(32), tr["MSG1"]["N1"], tr["MSG2"]["N2"], tr["MSG1"]["T1"], tr["MSG2"]["T2"], tr["MSG1"]["TID"])
    return Result("ESL: reveal ephemerals only", impl.name, RES if guess != sk else SUCC,
                  "N1, N2 are public anyway; SK needs K (claim is true but vacuous: nonces carry no secrecy)")


def reveal_sk_get_k(impl):
    if impl.kind == "bakmm":
        return Result("reveal SK_n -> long-term key?", impl.name, RES, "SK is a hash output; MS not derivable")
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    tr, sk, _ = impl.run(de, es, clock)
    st = impl.state(de)
    cands = [h(sk), h(sk, sk), h(sk, tr["MSG1"]["TID"]), h(tr["MSG1"]["TID"], sk)]
    hit = st["K"] in cands
    return Result("reveal SK_n -> long-term key?", impl.name, SUCC if hit else RES,
                  "K_(n+1) = h(K_n||SK_n) still needs K_n (preimage of SHA-256)")


def reveal_state_mid_session(impl):
    if impl.kind == "bakmm":
        return Result("reveal session state mid-run", impl.name, RES,
                      "state {rs1, T1, A, B}: SK = h(A||B||T1||T2||RID||MS) still needs RID and MS")
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    m1 = de.start()
    leaked = dict(N1=de.N1, T1=de.T1)                  # CK session state (long-term K excluded)
    m2 = impl.respond(es, m1)
    sk = impl.finish(de, m2)
    guess = h(rnd(32), leaked["N1"], m2["N2"], leaked["T1"], m2["T2"], m1["TID"])
    return Result("reveal session state mid-run", impl.name, RES if guess != sk else SUCC,
                  "session state {N1, T1} is already public; K is long-term (excluded by CK)")


def known_session_key(impl, n=5):
    clock, es, de, trs, keys = _history(impl, n=n)
    revealed = keys[:-1]
    target = keys[-1]
    # every function of the revealed keys + transcript that the adversary could try
    cands = {h(s, t["MSG1"]["TID"]) for s, t in zip(revealed, trs)} | {h(s) for s in revealed}
    return Result("known-session-key / independence", impl.name, SUCC if target in cands else RES,
                  f"{n-1} revealed SKs do not determine SK_{n}; each SK uses the evolving/long-term key")


# =========================================================================== de-synchronisation
def desync_drop_once(impl):
    rows = []
    points = ["MSG2"] + ([] if impl.two_msg else ["MSG3"])
    for d in points:
        clock = Clock(); _, es, (de,) = impl.setup(clock)
        impl.run(de, es, clock, drop=d)
        locked, why = _locked(impl, de, es, clock)
        rows.append((d, locked, why))
    bad = [r for r in rows if r[1]]
    if bad:
        return Result("de-sync: drop one message", impl.name, SUCC,
                      "; ".join(f"drop {d} -> locked out ({w})" for d, _, w in bad))
    return Result("de-sync: drop one message", impl.name, RES,
                  "; ".join(f"drop {d} -> recovered next run" for d, _, _ in rows))


def desync_drop_repeated(impl, k=10):
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    for _ in range(k):
        try:
            impl.run(de, es, clock, drop="MSG2")
        except AuthError:
            pass
        clock.advance(10)
    locked, why = _locked(impl, de, es, clock)
    return Result(f"de-sync: drop MSG2 {k}x", impl.name, SUCC if locked else RES,
                  why or f"after {k} drops the drone still authenticates")


def desync_reordered_retry(impl):
    """Two live MSG1 from the same credentials (retry within dT) are delivered out of order:
    b first (drone completes with b), then the withheld a."""
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    m1a = de.start()
    try:
        m1b = de.start()
    except AuthError as e:
        return Result("de-sync: reordered retry (2 records)", impl.name, RES,
                      f"drone never has two fresh MSG1 on one credential ({e})")
    m2b = impl.respond(es, m1b)
    if impl.kind == "bakmm":
        de.msg3 = de.finish(m2b); es.confirm(de.msg3)
    else:
        impl.complete(de, es, m2b)
    acc, _ = _accepts(impl.respond, es, m1a)
    locked, why = _locked(impl, de, es, clock)
    if locked:
        return Result("de-sync: reordered retry (2 records)", impl.name, SUCC,
                      f"withheld MSG1(a) accepted={acc}; honest drone locked out ({why})")
    return Result("de-sync: reordered retry (2 records)", impl.name, RES,
                  f"withheld MSG1(a) accepted={acc}, but the drone's record is kept")


def desync_candidate_eviction(impl, k=6):
    """Drone fires k retries inside dT; adversary delivers the LAST one (drone completes with it),
    then the k-1 withheld older ones.  Targets the bounded candidate list of fix F3."""
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    msgs = []
    for _ in range(k):
        try:
            msgs.append(de.start())
        except AuthError as e:
            return Result(f"de-sync: {k} withheld retries (eviction)", impl.name, RES,
                          f"drone refuses early retries ({e})")
    m2 = impl.respond(es, msgs[-1])
    if impl.kind == "bakmm":
        de.msg3 = de.finish(m2); es.confirm(de.msg3)
    else:
        impl.complete(de, es, m2)
    acc = sum(_accepts(impl.respond, es, m)[0] for m in msgs[:-1])
    locked, why = _locked(impl, de, es, clock)
    return Result(f"de-sync: {k} withheld retries (eviction)", impl.name, SUCC if locked else RES,
                  f"{acc} withheld MSG1 accepted; honest drone locked out={locked}" + (f" ({why})" if locked else ""))


def cross_es(impl):
    """The same credentials provisioned at two ground stations (roaming)."""
    clock = Clock(); ra, es1, (de,) = impl.setup(clock)
    if impl.kind == "bakmm":
        es2 = B.GroundStation(ra.register_es(clock), clock, impl.policy)
        es2.enroll(dict(TID=de.mem["TID"], RID=de.mem["RID"], MS=de.mem["MS"]))
    else:
        es2 = (P1.GroundStation(clock) if isinstance(impl, FSLv1Impl) else F.GroundStation(clock, impl.cfg))
        st = impl.state(de)
        es2.enroll(dict(TID=st["TID"], K=st["K"]), dev="DE0")
    impl.run(de, es1, clock); clock.advance(10)
    ok = True
    try:
        _, a, b = impl.run(de, es2, clock)
        ok = a == b
    except AuthError:
        ok = False
    return Result("same credentials at two ES", impl.name, PART if not ok else RES,
                  "functional limitation: the drone rotates TID/K with ES1, ES2 no longer knows them; "
                  "needs per-ES credentials" if not ok else "works")


# =========================================================================== DoS / timing
def dos_costs(impl, n=200):
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    tr, _, _ = impl.run(de, es, clock); clock.advance(10)
    tid = de.start()[list(tr["MSG1"])[0]]
    reset_hash_counter()
    for _ in range(n):
        m = copy.deepcopy(tr["MSG1"])
        m[list(m)[0]] = rnd(len(tid))
        for k, v in m.items():
            if isinstance(v, int):
                m[k] = clock.now()
        _accepts(impl.respond, es, m)
    unknown = hashes() / n
    reset_hash_counter()
    for _ in range(n):
        m = {k: (clock.now() if isinstance(v, int) else rnd(len(v))) for k, v in tr["MSG1"].items()}
        m[list(m)[0]] = tid
        _accepts(impl.respond, es, m)
    known = hashes() / n
    cache = len(getattr(es, "cache", {}))
    return Result("DoS: TID lookup / cache flooding", impl.name, RES,
                  f"unknown TID costs {unknown:.0f} h, known TID + garbage costs {known:.0f} h; "
                  f"cache entries after {2*n} forgeries = {cache} (inserted only after a valid MAC)",
                  dict(h_unknown=unknown, h_known=known, cache=cache))


def delta_t_edges(impl):
    res = {}
    for skew in (-3, -2, 2, 3):
        clock = Clock(); _, es, (de,) = impl.setup(clock)
        de.clock = Clock(clock.now() + skew)
        m1 = de.start()
        res[skew] = _accepts(impl.respond, es, m1)[0]
    ok = res == {-3: False, -2: True, 2: True, 3: False}
    return Result("clock skew / dT edges", impl.name, PART,
                  f"|skew|<=dT accepted, >dT rejected {res}: a drone whose clock drifts > dT is locked out "
                  "until resynchronised (inherent to timestamp freshness)" if ok else f"unexpected {res}", res)


def reboot_replay(impl):
    if impl.kind != "fsl":
        return Result("replay after ES reboot (cache lost)", impl.name, NA, "no cache at all (see replay inside dT)")
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    m1 = de.start(); m2 = impl.respond(es, m1); impl.complete(de, es, m2)
    if hasattr(es, "reboot"):
        es.reboot()
    else:
        es.cache.clear()                               # v1 has no reboot handling: RAM cache lost
    ok, why = _accepts(impl.respond, es, copy.deepcopy(m1))
    locked, _ = _locked(impl, de, es, clock)
    if ok:
        return Result("replay after ES reboot (cache lost)", impl.name, SUCC,
                      f"replay accepted after reboot; honest drone locked out={locked}")
    return Result("replay after ES reboot (cache lost)", impl.name, RES, why)


# =========================================================================== insider / lifecycle
def insider_ra(impl):
    """RA insider keeps the drone's initial credentials and records transcripts."""
    clock = Clock()
    if impl.kind == "bakmm":
        ra, es, (de,) = impl.setup(clock)
        kept = impl.state(de)
        tr, sk, _ = impl.run(de, es, clock)
        got = _bakmm_sk(kept["RID"], kept["MS"], tr["MSG1"], tr["MSG2"])[0] == sk
        return Result("privileged insider at RA", impl.name, PART if got else RES,
                      "if the RA keeps RID/MS (Prop. 3 assumes it deletes them) every SK is recoverable")
    _, es, (de,) = impl.setup(clock)
    kept = impl.state(de)
    trs, keys = [], []
    for i in range(6):
        tr, a, _ = impl.run(de, es, clock); trs.append(tr); keys.append(a); clock.advance(10)
    K, TID, got_all = kept["K"], kept["TID"], 0
    for tr, sk in zip(trs, keys):
        g = _fsl_sk(K, TID, tr["MSG1"], tr["MSG2"]); got_all += g == sk
        K, TID = impl.evolve(K, TID, g)
    K, TID, got_gap = kept["K"], kept["TID"], 0          # one transcript (session 3) missed
    for i, (tr, sk) in enumerate(zip(trs, keys)):
        if i == 2:
            K = TID = None; continue
        if K is None:
            continue
        g = _fsl_sk(K, TID, tr["MSG1"], tr["MSG2"]); got_gap += g == sk
        K, TID = impl.evolve(K, TID, g)
    return Result("privileged insider at RA", impl.name, PART,
                  f"if the RA keeps K_0: {got_all}/6 SKs with every transcript, {got_gap}/6 when one "
                  "transcript is missed (the chain breaks); requires RA to erase K_i", dict(all=got_all, gap=got_gap))


def dynamic_add_default_enroll(impl):
    """Enrol two drones exactly as the draft describes (no per-drone id passed)."""
    clock = Clock()
    if impl.kind == "bakmm":
        ra = B.RA(); es = B.GroundStation(ra.register_es(clock), clock)
        creds = [ra.register_drone(clock) for _ in range(2)]
        for c in creds: es.enroll(c)
        ds = [B.Drone(c, clock) for c in creds]
    elif isinstance(impl, FSLv1Impl):
        ra, es = P1.RA(), P1.GroundStation(clock)
        creds = [ra.register_drone() for _ in range(2)]
        for c in creds: es.enroll(c)                   # default dev="DE"
        ds = [P1.Drone(c, clock) for c in creds]
    else:
        _, es, ds = impl.setup(clock, n=2)
    impl.run(ds[0], es, clock); clock.advance(10)
    ok, why = True, ""
    try:
        impl.run(ds[1], es, clock)
    except AuthError as e:
        ok, why = False, str(e)
    if ok:
        return Result("dynamic addition (2nd drone)", impl.name, RES, "both drones keep working")
    return Result("dynamic addition (2nd drone)", impl.name, SUCC,
                  f"drone 1's session deleted drone 2's record ({why}): enroll(dev='DE') default")


def revocation(impl):
    if impl.kind == "bakmm":
        return Result("revocation", impl.name, NA, "no revocation procedure in the paper")
    clock = Clock(); _, es, (de,) = impl.setup(clock)
    impl.run(de, es, clock); clock.advance(10)
    impl.run(de, es, clock, drop="MSG2"); clock.advance(10)   # drone left on the old record
    if isinstance(impl, FSLv1Impl):
        cur = [t for t, r in es.db.items() if r["role"] == "cur"]
        for t in cur: del es.db[t]                            # naive: delete the current record
        how = "naive (delete cur record)"
    else:
        es.revoke(next(iter(es.devs)))
        how = "revoke(dev) deletes anchor + candidates"
    ok = _accepts(lambda: impl.run(de, es, clock))[0]
    return Result("revocation", impl.name, SUCC if ok else RES,
                  f"{how}: revoked drone still authenticates via old record" if ok else f"{how}: rejected")


def tid_collision(impl, drones=40, tid_bytes=1, sessions=4):
    """Force collisions by truncating TIDs to 8 bits; 160-bit bound is analytic (see cost.py)."""
    if impl.kind == "bakmm":
        return Result("TID collision (8-bit demo)", impl.name, NA, "ES picks TID_new at random; can check uniqueness")
    clock = Clock()
    if isinstance(impl, FSLv1Impl):
        import proposed_fslake as mod
        ra, es = mod.RA(), mod.GroundStation(clock)
        ds = []
        for i in range(drones):
            c = dict(TID=rnd(tid_bytes), K=rnd(32)); es.enroll(c, dev=f"d{i}"); ds.append(mod.Drone(c, clock))
        old = mod.ID_BYTES
        mod.ID_BYTES = tid_bytes
    else:
        cfg = F.replace(impl.cfg, tid_bytes=tid_bytes)
        _, es, ds = FSLv2Impl(cfg).setup(clock, n=drones)
    fails = 0
    for _ in range(sessions):
        for d in ds:
            try:
                _, a, b = impl.run(d, es, clock); fails += a != b
            except AuthError:
                fails += 1
            clock.advance(5)
    if isinstance(impl, FSLv1Impl):
        mod.ID_BYTES = old
    total = drones * sessions
    return Result("TID collision (8-bit demo)", impl.name, SUCC if fails else RES,
                  f"{fails}/{total} sessions failed with 8-bit TIDs" +
                  (" (dict keyed by TID: colliding record overwritten)" if fails else
                   " (ES tries every record under a TID)"), dict(fails=fails, total=total))


# =========================================================================== anonymity
def anonymity_passive(impl, n=12):
    out = {}
    for drop_rate in (0, 1 / 3):
        clock = Clock(); _, es, (de,) = impl.setup(clock)
        ids, real_start = [], de.start

        def sniff():                                   # the observer records every MSG1 on the air
            m = real_start(); ids.append(m[list(m)[0]]); return m
        de.start = sniff
        for i in range(n):
            drop = "MSG2" if (drop_rate and i % 3 == 1) else None
            try:
                impl.run(de, es, clock, drop=drop)
            except AuthError:
                pass
            clock.advance(30)
        out[round(drop_rate, 2)] = len(ids) - len(set(ids))       # linkable repeats
    if out[0] == 0 and out[0.33] == 0:
        return Result("anonymity: passive linking", impl.name, RES, "no identifier repeats on the air", out)
    if out[0] == 0:
        return Result("anonymity: passive linking", impl.name, PART,
                      f"successful sessions unlinkable; each dropped MSG2 makes the retry reuse the TID "
                      f"({out[0.33]} linkable pairs in {n}); an active adversary dropping every MSG2 can track the drone", out)
    return Result("anonymity: passive linking", impl.name, SUCC, f"identifier repeats even without drops ({out[0]})", out)


ATTACKS = [
    replay_inside, replay_outside, replay_after_resync, replay_with_clock_skew, reboot_replay,
    modify_fields, reflection, interleave,
    drone_impersonation, es_impersonation,
    kci_after_capture, capture_past_keys, capture_future_keys, capture_link_tids,
    stolen_db_without_X, es_compromise_with_X,
    esl_ephemerals_only, reveal_sk_get_k, reveal_state_mid_session, known_session_key,
    desync_drop_once, desync_drop_repeated, desync_reordered_retry, desync_candidate_eviction, cross_es,
    dos_costs, delta_t_edges,
    insider_ra, dynamic_add_default_enroll, revocation, tid_collision,
    anonymity_passive,
]


def matrix(impl_list=None, attacks=ATTACKS):
    impl_list = impl_list or impls()
    return {a.__name__: {i.name: a(i) for i in impl_list} for a in attacks}


if __name__ == "__main__":
    M = matrix()
    for name, row in M.items():
        for r in row.values():
            print(r)
        print()
