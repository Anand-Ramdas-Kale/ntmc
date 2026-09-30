"""Faithful simulation of the BAKMM-IoD drone <-> ground-station (DE_i <-> ES_j)
authentication and key establishment phase (Wazid et al., J. Syst. Archit. 160
(2025) 103365, Section 4.2 / Table 5).

Message flow:
  MSG1 = {TID, M1, M2, T1}     DE -> ES
  MSG2 = {M3, M4, M5, T2}      ES -> DE
  MSG3 = {M6, T3}              DE -> ES

The paper does not say *when* ES replaces TID with TID_new in its database.
Both readings are modelled via `tid_update`:
  "on_send"    : ES overwrites TID when it sends MSG2
  "on_confirm" : ES overwrites TID only after verifying MSG3
"""
from common import (h, xor, rnd, AuthError, ID_BYTES, HASH_BYTES)

DELTA_T = 2  # seconds, maximum transmission delay


class RA:
    def __init__(self):
        self.ID = rnd(ID_BYTES)
        self.SN = rnd()
        self.k = rnd()
        self.RID = h(self.ID, self.SN, self.k)[:ID_BYTES]

    def register_drone(self, clock):
        ID, k, SN = rnd(ID_BYTES), rnd(), rnd()
        RID = h(self.RID, ID, self.k, k, SN)
        TC = h(self.RID, ID, self.k, k, SN, clock.now())
        TID = rnd(ID_BYTES)
        MS = rnd(HASH_BYTES)                      # MS_{DE_i-ES_j}
        return dict(TID=TID, RID=RID, TC=TC, MS=MS)

    def register_es(self, clock):
        ID, k, SN = rnd(ID_BYTES), rnd(), rnd()
        RID = h(self.RID, ID, self.k, k, SN)
        TC = h(self.RID, ID, self.k, k, SN, clock.now())
        return dict(RID=RID, TC=TC)


class Drone:
    def __init__(self, cred, clock):
        self.mem = dict(cred)                     # {TID, RID, TC, MS} -- plain in memory
        self.clock = clock
        self.session_key = None

    # AKDDE1
    def start(self):
        m = self.mem
        self.T1 = self.clock.now()
        self.rs1 = rnd()
        self.A = h(m["TC"], self.rs1, m["MS"], self.T1)
        M1 = xor(h(m["RID"], m["MS"], self.T1), self.A)
        M2 = h(self.A, m["RID"], self.T1)
        return dict(TID=m["TID"], M1=M1, M2=M2, T1=self.T1)

    # AKDDE3
    def finish(self, msg2):
        m = self.mem
        if abs(msg2["T2"] - self.clock.now()) > DELTA_T:
            raise AuthError("DE: stale T2")
        T2 = msg2["T2"]
        B = xor(msg2["M3"], h(m["RID"], m["MS"], T2))
        SK = h(self.A, B, self.T1, T2, m["RID"], m["MS"])
        if h(SK, self.T1, T2, m["RID"]) != msg2["M4"]:
            raise AuthError("DE: M4 mismatch")
        TID_new = xor(msg2["M5"], h(self.A, m["RID"], T2)[:ID_BYTES])
        m["TID"] = TID_new
        self.session_key = SK
        T3 = self.clock.now()
        return dict(M6=h(SK, T3), T3=T3)


class GroundStation:
    def __init__(self, cred, clock, tid_update="on_confirm"):
        self.RID = cred["RID"]
        self.TC = cred["TC"]
        self.db = {}                              # TID -> {RID, MS}  (plain verifier table)
        self.clock = clock
        self.tid_update = tid_update
        self.accepted = []                        # log of accepted MSG1 (for replay demo)
        self.pending = None
        self.session_keys = []

    def enroll(self, cred):
        self.db[cred["TID"]] = dict(RID=cred["RID"], MS=cred["MS"])

    # AKDDE2
    def respond(self, msg1):
        if abs(msg1["T1"] - self.clock.now()) > DELTA_T:
            raise AuthError("ES: stale T1")
        rec = self.db.get(msg1["TID"])
        if rec is None:
            raise AuthError("ES: unknown TID (desynchronised)")
        RID, MS, T1 = rec["RID"], rec["MS"], msg1["T1"]
        A = xor(msg1["M1"], h(RID, MS, T1))
        if h(A, RID, T1) != msg1["M2"]:
            raise AuthError("ES: M2 mismatch")
        self.accepted.append(msg1)
        T2, rs2 = self.clock.now(), rnd()
        B = h(self.RID, self.TC, rs2, MS, T2)
        M3 = xor(h(RID, MS, T2), B)
        SK = h(A, B, T1, T2, RID, MS)
        M4 = h(SK, T1, T2, RID)
        TID_new = rnd(ID_BYTES)
        M5 = xor(TID_new, h(A, RID, T2)[:ID_BYTES])
        self.pending = dict(old=msg1["TID"], new=TID_new, SK=SK, rec=rec)
        if self.tid_update == "on_send":
            self._rotate()
        return dict(M3=M3, M4=M4, M5=M5, T2=T2)

    def _rotate(self):
        p = self.pending
        self.db.pop(p["old"], None)
        self.db[p["new"]] = p["rec"]

    # AKDDE4
    def confirm(self, msg3):
        if abs(msg3["T3"] - self.clock.now()) > DELTA_T:
            raise AuthError("ES: stale T3")
        if h(self.pending["SK"], msg3["T3"]) != msg3["M6"]:
            raise AuthError("ES: M6 mismatch")
        if self.tid_update == "on_confirm":
            self._rotate()
        self.session_keys.append(self.pending["SK"])
        return self.pending["SK"]


def run_session(de, es, clock, drop=None):
    """Run one DE<->ES session. drop in {None,'MSG2','MSG3'} simulates an adversary
    deleting that message. Returns (transcript, SK_DE, SK_ES)."""
    msg1 = de.start(); clock.advance()
    msg2 = es.respond(msg1); clock.advance()
    tr = dict(MSG1=msg1, MSG2=msg2)
    if drop == "MSG2":
        return tr, None, None
    msg3 = de.finish(msg2); clock.advance()
    tr["MSG3"] = msg3
    if drop == "MSG3":
        return tr, de.session_key, None
    sk_es = es.confirm(msg3)
    return tr, de.session_key, sk_es


def setup(clock, tid_update="on_confirm"):
    ra = RA()
    es = GroundStation(ra.register_es(clock), clock, tid_update)
    cred = ra.register_drone(clock)
    es.enroll(cred)
    de = Drone(cred, clock)
    return ra, es, de
