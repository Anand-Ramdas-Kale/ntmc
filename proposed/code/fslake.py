"""FSL-AKE-IoD v2 - the proposed protocol after independent review.

This file keeps the message formulas of proposed_fslake.py (v1) unchanged:

  MSG1 = {TID, N1, T1, V1},   V1 = h(K || TID || N1 || T1)
  MSG2 = {N2, T2, V2},        SK = h(K || N1 || N2 || T1 || T2 || TID),  V2 = h(SK || N2 || T2)
  after the session:          K <- h(K || SK),   TID <- h(TID || SK)[:160 bit]

It fixes three flaws that the review found in v1 (see attacks_fslake.py):

  F1  v1 GroundStation.enroll() defaults dev="DE" for every drone, so one drone's session
      deletes the records of all other drones.  v2 gives every drone a unique device id.
  F2  v1 keeps a replay-cache entry until (receive time + dT).  With legitimate clock skew
      (drone ahead of ES), the message is still fresh after the entry expires, so an
      in-window replay is accepted.  v2 keeps the entry until (T1 + dT), which covers the
      whole acceptance window.
  F3  v1 keeps exactly one old and one current record.  If a drone sends two MSG1 on the
      same credentials (a retry) and the adversary delivers them out of order, the ES
      deletes the record the drone actually holds (permanent lock-out).  v2 keeps the
      last *confirmed* record (anchor) plus every candidate derived from it, and promotes
      a candidate only when the drone proves possession of it (valid V1 under it).
  F4  (found while reviewing F3) the candidate list is bounded; if a drone fires more than
      MAX_CANDIDATES retries inside the freshness window, delivering the withheld ones late can
      evict the candidate the drone holds.  v2 drones therefore wait > 2*dT before re-sending
      MSG1 on the same credentials, so at most one of their MSG1 is fresh at the ES at any time
      (independent of clock skew, because both freshness tests use the ES clock and T1).

Each of the six design modifications of the draft can be switched off (ablation):

  M1 one-way key evolution K <- h(K||SK)      M4 replay cache
  M2 implicit TID update h(TID||SK)           M5 masked verifier C = K XOR h(X_ES||TID)
  M3 dual old/cur record (v2: anchor+cands)   M6 two-message flow (off = add MSG3 key confirmation)

The same classes are used for ES<->CS key management (Initiator = ES, Responder = CS).
"""
from dataclasses import dataclass, replace
from common import h, xor, rnd, AuthError, ID_BYTES, HASH_BYTES

DELTA_T = 2          # seconds
MAX_CANDIDATES = 4   # candidate records kept per device (F3); see README for the DE retry rule


@dataclass(frozen=True)
class Config:
    M1_key_evolution: bool = True
    M2_tid_update: bool = True
    M3_dual_record: bool = True
    M4_replay_cache: bool = True
    M5_masked_verifier: bool = True
    M6_two_message: bool = True
    F2_cache_expiry_from_T1: bool = True
    F3_candidate_set: bool = True
    F4_retry_gap: bool = True
    retry_pseudonyms: int = 0        # optional anonymity extension (0 = off, as in the draft)
    tid_bytes: int = ID_BYTES
    delta_t: int = DELTA_T


V2 = Config()
# v2 code with the protocol-level fixes switched off behaves like v1 (F1 is structural)
V1_EQUIVALENT = Config(F2_cache_expiry_from_T1=False, F3_candidate_set=False, F4_retry_gap=False)


def without(**kw):
    """Config with some modifications switched off, e.g. without(M1_key_evolution=False)."""
    return replace(V2, **kw)


def pid(TID, j, n):
    """j-th retry pseudonym of TID (only used when cfg.retry_pseudonyms > 0)."""
    return h(TID, j)[:n]


class RA:
    """Offline registration authority. `retain=True` models a privileged insider who keeps K_0."""

    def __init__(self, cfg=V2, retain=False):
        self.cfg, self.retain, self.kept = cfg, retain, {}
        self._n = 0

    def register_drone(self):
        self._n += 1
        cred = dict(TID=rnd(self.cfg.tid_bytes), K=rnd(HASH_BYTES), dev=f"dev{self._n}-{rnd(4).hex()}")
        if self.retain:
            self.kept[cred["dev"]] = dict(cred)
        return cred


class Drone:
    """Initiator role (a drone DE_i, or ES_j when it talks to CS_k)."""

    def __init__(self, cred, clock, cfg=V2):
        self.TID, self.K = cred["TID"], cred["K"]
        self.clock, self.cfg = clock, cfg
        self.N1 = self.T1 = self.ID = None
        self.ctr = 0                      # consecutive attempts on the current (TID, K)
        self.session_key = None

    @property
    def mem(self):
        return dict(TID=self.TID, K=self.K)

    def start(self):
        cfg = self.cfg
        if (cfg.F4_retry_gap and self.ctr > 0 and self.T1 is not None
                and self.clock.now() - self.T1 <= 2 * cfg.delta_t):
            raise AuthError("DE: retry on the same credentials before 2*dT has passed (rule F4)")
        w = cfg.retry_pseudonyms
        self.ID = self.TID if (w == 0 or self.ctr == 0) else pid(self.TID, min(self.ctr, w), self.cfg.tid_bytes)
        self.ctr += 1
        self.N1, self.T1 = rnd(), self.clock.now()
        V1 = h(self.K, self.ID, self.N1, self.T1)
        return dict(TID=self.ID, N1=self.N1, T1=self.T1, V1=V1)

    def finish(self, msg2):
        cfg = self.cfg
        if self.N1 is None:
            raise AuthError("DE: no session in progress")
        if abs(msg2["T2"] - self.clock.now()) > cfg.delta_t:
            raise AuthError("DE: stale T2")
        SK = h(self.K, self.N1, msg2["N2"], self.T1, msg2["T2"], self.TID)
        if h(SK, msg2["N2"], msg2["T2"]) != msg2["V2"]:
            raise AuthError("DE: V2 mismatch")
        msg3 = None
        if not cfg.M6_two_message:
            T3 = self.clock.now()
            msg3 = dict(V3=h(SK, T3), T3=T3)
        if cfg.M1_key_evolution:
            self.K = h(self.K, SK)                          # old K overwritten
        if cfg.M2_tid_update:
            self.TID = h(self.TID, SK)[:cfg.tid_bytes]
        self.N1, self.ctr, self.session_key = None, 0, SK
        return SK if msg3 is None else (SK, msg3)


class GroundStation:
    """Responder role (ES_j for drones, or CS_k for ground stations)."""

    def __init__(self, clock, cfg=V2):
        self.X = rnd(HASH_BYTES)          # master secret; assumed to live in a secure element
        self.clock, self.cfg = clock, cfg
        self.devs = {}                    # dev -> {"anchor": rec, "cands": [rec, ...]}
        self.index = {}                   # identifier on the wire -> [rec, ...]
        self.cache = {}                   # (ID, T1, N1) -> expiry
        self.pending = []                 # 3-message variant only
        self.session_keys = []
        self.quiet_until = None

    # ---------------------------------------------------------------- storage
    def _hide(self, K, TID):
        return xor(K, h(self.X, TID)) if self.cfg.M5_masked_verifier else K

    def _reveal(self, rec):
        return xor(rec["C"], h(self.X, rec["TID"])) if self.cfg.M5_masked_verifier else rec["C"]

    def _new_rec(self, dev, TID, K):
        w, n = self.cfg.retry_pseudonyms, self.cfg.tid_bytes
        rec = dict(dev=dev, TID=TID, C=self._hide(K, TID))
        rec["ids"] = [TID] + [pid(TID, j, n) for j in range(1, w + 1)]
        for i in rec["ids"]:
            self.index.setdefault(i, []).append(rec)
        return rec

    def _drop_rec(self, rec):
        for i in rec["ids"]:
            lst = [r for r in self.index.get(i, []) if r is not rec]
            if lst:
                self.index[i] = lst
            else:
                self.index.pop(i, None)

    def records(self):
        """Database dump as an attacker would see it: (TID, C) per stored record."""
        return [(r["TID"], r["C"]) for d in self.devs.values() for r in [d["anchor"], *d["cands"]]]

    def enroll(self, cred, dev=None):
        dev = dev or cred.get("dev") or cred["TID"].hex()
        if dev in self.devs:
            raise ValueError("device id already enrolled")
        self.devs[dev] = dict(anchor=self._new_rec(dev, cred["TID"], cred["K"]), cands=[])
        return dev

    def revoke(self, dev):
        d = self.devs.pop(dev)
        for r in [d["anchor"], *d["cands"]]:
            self._drop_rec(r)

    def reboot(self):
        """RAM (and so the replay cache) is lost; refuse MSG1 for 2*dT so no cached entry is missed."""
        self.cache.clear()
        self.pending.clear()
        self.quiet_until = self.clock.now() + 2 * self.cfg.delta_t

    def _advance(self, rec, K_new, TID_new):
        cfg, d = self.cfg, self.devs[rec["dev"]]
        new = self._new_rec(rec["dev"], TID_new, K_new)
        if not cfg.M3_dual_record:                          # single record, replaced immediately
            for r in [d["anchor"], *d["cands"]]:
                self._drop_rec(r)
            d["anchor"], d["cands"] = new, []
        elif rec is d["anchor"]:
            if cfg.F3_candidate_set:
                d["cands"].append(new)
                while len(d["cands"]) > MAX_CANDIDATES:
                    self._drop_rec(d["cands"].pop(0))
            else:                                           # v1: exactly one old + one current
                for r in d["cands"]:
                    self._drop_rec(r)
                d["cands"] = [new]
        else:                                               # drone proved it holds a candidate
            for r in [d["anchor"], *[c for c in d["cands"] if c is not rec]]:
                self._drop_rec(r)
            d["anchor"], d["cands"] = rec, [new]
        return new

    def _promote(self, new):
        """3-message variant: key confirmation received -> forget the old key at once."""
        d = self.devs.get(new["dev"])
        if d is None or (new is not d["anchor"] and new not in d["cands"]):
            return
        for r in [d["anchor"], *[c for c in d["cands"] if c is not new]]:
            self._drop_rec(r)
        d["anchor"], d["cands"] = new, []

    # ---------------------------------------------------------------- protocol
    def respond(self, msg1):
        cfg, now = self.cfg, self.clock.now()
        if self.quiet_until is not None and now <= self.quiet_until:
            raise AuthError("ES: quiet period after reboot")
        ID, N1, T1 = msg1["TID"], msg1["N1"], msg1["T1"]
        if abs(T1 - now) > cfg.delta_t:
            raise AuthError("ES: stale T1")
        if cfg.M4_replay_cache:
            self.cache = {k: v for k, v in self.cache.items() if v >= now}
            if (ID, T1, N1) in self.cache:
                raise AuthError("ES: replay detected (cache)")
        recs = self.index.get(ID)
        if not recs:
            raise AuthError("ES: unknown TID")
        for rec in list(recs):
            K = self._reveal(rec)
            if h(K, ID, N1, T1) == msg1["V1"]:
                break
        else:
            raise AuthError("ES: V1 mismatch")
        if cfg.M4_replay_cache:
            self.cache[(ID, T1, N1)] = (T1 if cfg.F2_cache_expiry_from_T1 else now) + cfg.delta_t
        N2, T2, TID = rnd(), now, rec["TID"]
        SK = h(K, N1, N2, T1, T2, TID)
        V2 = h(SK, N2, T2)
        K_new = h(K, SK) if cfg.M1_key_evolution else K
        TID_new = h(TID, SK)[:cfg.tid_bytes] if cfg.M2_tid_update else TID
        new = self._advance(rec, K_new, TID_new)
        if cfg.M6_two_message:
            self.session_keys.append(SK)
        else:
            self.pending.append(dict(SK=SK, new=new, exp=now + 2 * cfg.delta_t))
        return dict(N2=N2, T2=T2, V2=V2), SK

    def confirm(self, msg3):
        """Only used when M6 is switched off (three-message variant)."""
        now = self.clock.now()
        if abs(msg3["T3"] - now) > self.cfg.delta_t:
            raise AuthError("ES: stale T3")
        self.pending = [p for p in self.pending if p["exp"] >= now]
        for p in self.pending:
            if h(p["SK"], msg3["T3"]) == msg3["V3"]:
                self.pending.remove(p)
                self._promote(p["new"])
                self.session_keys.append(p["SK"])
                return p["SK"]
        raise AuthError("ES: V3 mismatch")


Initiator, Responder = Drone, GroundStation


def run_session(de, es, clock, drop=None):
    """One session. drop in {None, 'MSG2', 'MSG3'}. Returns (transcript, SK_DE, SK_ES)."""
    msg1 = de.start(); clock.advance()
    msg2, sk_es = es.respond(msg1); clock.advance()
    tr = dict(MSG1=msg1, MSG2=msg2)
    two = es.cfg.M6_two_message
    if drop == "MSG2":
        return tr, None, sk_es if two else None
    out = de.finish(msg2)
    if two:
        return tr, out, sk_es
    sk_de, msg3 = out
    clock.advance()
    tr["MSG3"] = msg3
    if drop == "MSG3":
        return tr, sk_de, None
    return tr, sk_de, es.confirm(msg3)


def setup(clock, cfg=V2, n=1, retain=False):
    """Returns (ra, es, de) for n == 1, else (ra, es, [drones])."""
    ra, es = RA(cfg, retain), GroundStation(clock, cfg)
    drones = []
    for _ in range(n):
        cred = ra.register_drone()
        es.enroll(cred)
        drones.append(Drone(cred, clock, cfg))
    return ra, es, (drones[0] if n == 1 else drones)
