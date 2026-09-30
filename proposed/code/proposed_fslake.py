"""FSL-AKE-IoD: Forward-Secure, Lightweight, desync-resilient Authenticated Key
Establishment for the Internet of Drones (proposed improvement of BAKMM-IoD).

Registration (RA, offline, secure channel)
  RA picks K_i (256 bit) and TID_i (160 bit).
  DE_i stores {TID_i, K_i}.
  ES_j holds a master secret X_ES inside its secure element (TPM/HSM) and stores
  only the masked verifier  C_i = K_i XOR h(X_ES || TID_i)  indexed by TID_i.

Authentication (2 messages)
  DE : pick N1, T1;  V1 = h(K || TID || N1 || T1)
       MSG1 = {TID, N1, T1, V1}                              -> ES
  ES : |T1 - T*| <= dT and (TID,T1,N1) not in replay cache
       K = C XOR h(X_ES || TID); check V1
       pick N2, T2;  SK = h(K || N1 || N2 || T1 || T2 || TID)
       V2 = h(SK || N2 || T2)
       MSG2 = {N2, T2, V2}                                   -> DE
       K' = h(K || SK);  TID' = h(TID || SK)[:160 bit]
       keep {old: (TID, C)}, {cur: (TID', K' XOR h(X_ES||TID'))}
  DE : check T2, recompute SK, check V2
       K <- h(K || SK); TID <- h(TID || SK); erase old K, N1

Why it fixes BAKMM-IoD
  * Forward secrecy: K evolves one-way after each session; capturing DE at time t
    yields only K_t, from which no earlier K (hence no earlier SK) can be computed.
  * Untraceability after capture: TID' = h(TID||SK) is never transmitted and needs SK.
  * De-sync resilience: ES keeps (old, cur) records; a lost MSG2 is recovered next run.
  * Replay inside dT: small cache of (TID,T1,N1) for dT seconds.
  * Stolen verifier: ES table holds only masked C_i; useless without X_ES.
"""
from common import h, xor, rnd, AuthError, ID_BYTES, HASH_BYTES

DELTA_T = 2


class RA:
    def register_drone(self):
        return dict(TID=rnd(ID_BYTES), K=rnd(HASH_BYTES))


class Drone:
    def __init__(self, cred, clock):
        self.mem = dict(cred)                      # {TID, K}
        self.clock = clock
        self.session_key = None

    def start(self):
        m = self.mem
        self.N1, self.T1 = rnd(), self.clock.now()
        V1 = h(m["K"], m["TID"], self.N1, self.T1)
        return dict(TID=m["TID"], N1=self.N1, T1=self.T1, V1=V1)

    def finish(self, msg2):
        m = self.mem
        if abs(msg2["T2"] - self.clock.now()) > DELTA_T:
            raise AuthError("DE: stale T2")
        SK = h(m["K"], self.N1, msg2["N2"], self.T1, msg2["T2"], m["TID"])
        if h(SK, msg2["N2"], msg2["T2"]) != msg2["V2"]:
            raise AuthError("DE: V2 mismatch")
        m["K"] = h(m["K"], SK)                    # one-way key evolution
        m["TID"] = h(m["TID"], SK)[:ID_BYTES]     # silent pseudonym update
        self.N1 = None                            # erase ephemeral
        self.session_key = SK
        return SK


class GroundStation:
    def __init__(self, clock):
        self.X = rnd(HASH_BYTES)                  # lives in secure element only
        self.db = {}                              # TID -> {C, peer, role}
        self.clock = clock
        self.cache = {}                           # (TID,T1,N1) -> expiry
        self.session_keys = []

    def _mask(self, K, TID):
        return xor(K, h(self.X, TID))

    def enroll(self, cred, dev="DE"):
        self.db[cred["TID"]] = dict(C=self._mask(cred["K"], cred["TID"]), dev=dev, role="cur")

    def respond(self, msg1):
        now = self.clock.now()
        T1, TID, N1 = msg1["T1"], msg1["TID"], msg1["N1"]
        if abs(T1 - now) > DELTA_T:
            raise AuthError("ES: stale T1")
        self.cache = {k: v for k, v in self.cache.items() if v >= now}
        if (TID, T1, N1) in self.cache:
            raise AuthError("ES: replay detected (cache)")
        rec = self.db.get(TID)
        if rec is None:
            raise AuthError("ES: unknown TID")
        K = xor(rec["C"], h(self.X, TID))
        if h(K, TID, N1, T1) != msg1["V1"]:
            raise AuthError("ES: V1 mismatch")
        self.cache[(TID, T1, N1)] = now + DELTA_T
        N2, T2 = rnd(), now
        SK = h(K, N1, N2, T1, T2, TID)
        V2 = h(SK, N2, T2)
        K_new, TID_new = h(K, SK), h(TID, SK)[:ID_BYTES]
        dev = rec["dev"]
        # keep exactly one old + one current record per device
        for t in [t for t, r in self.db.items() if r["dev"] == dev and t != TID]:
            del self.db[t]
        self.db[TID] = dict(C=rec["C"], dev=dev, role="old")
        self.db[TID_new] = dict(C=self._mask(K_new, TID_new), dev=dev, role="cur")
        self.session_keys.append(SK)
        return dict(N2=N2, T2=T2, V2=V2), SK


def run_session(de, es, clock, drop=None):
    msg1 = de.start(); clock.advance()
    msg2, sk_es = es.respond(msg1); clock.advance()
    tr = dict(MSG1=msg1, MSG2=msg2)
    if drop == "MSG2":
        return tr, None, sk_es
    sk_de = de.finish(msg2)
    return tr, sk_de, sk_es


def setup(clock):
    ra = RA()
    es = GroundStation(clock)
    cred = ra.register_drone()
    es.enroll(cred)
    return ra, es, Drone(cred, clock)
