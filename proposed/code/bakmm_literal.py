"""BAKMM-IoD exactly as printed (Wazid et al., JSA 160 (2025) 103365), for the parts that
bakmm_iod.py silently harmonised or did not implement.

1. DE<->ES session key (Sec. 4.2 text and Table 5)
     ES (AKDDE2):  SK = h(A || B || T1 || T2 || RID_DE || MS)
     DE (AKDDE3):  SK = h(A || B || RID_DE || T1 || T2 || MS)      <- different order
   bakmm_iod.py uses the ES order on both sides.  LiteralDrone uses the DE order as printed.

2. ES<->CS key management (Sec. 4.3, AKDEC1-AKDEC4) - not implemented in bakmm_iod.py.
   As printed:
     m1 = h(TC_ES || RS1 || MS || TS1) XOR h(RID_ES || MS || TS1)
     m2 = h(h(RS1 || TC_ES || MS || TS1) || RID_ES || MS || TS1)          <- inner order differs from m1
     CS: h(RS1||TC_ES||MS||TS1) = m1 XOR h(RID_ES||MS||TS1)
         m2' = h(h(rs1 || TC_ES || MS || TS1) || RID_ES || MS || TS1)     <- 'rs1' (typo)
     m3 = h(RS2 || TC_CS || MS_{ESj-ESj} || TS2) XOR h(RID_ES || MS || TS1 || TS2)   <- 'MS_{ESj-ESj}'
     SK = h(h(RS2||TC_CS||MS||TS2) || h(RS1||TC_ES||MS||TS1) || RID_ES || MS || TS1 || TS2)
     m4 = h(SK || RID_ES || MS || TS2)
     m5 = TIN_new XOR h(RID_ES || h(RS1||TC_ES||MS||TS1) || TS2)
     ES (AKDEC3): TIN_new = m5 XOR h(RID_ES || h(RS2||TC_ES||MS||TS1) || TS2)  <- needs RS2 (CS secret)
     m6 = h(SK || TS3)
   Each erratum can be switched on separately:
     E1 m1/m2 inner-hash order;  E4 ES recovers TIN_new with RS2.
   ('rs1' and 'MS_{ESj-ESj}' are notational: there is no second key the CS could use, so they are
   read as RS1 and MS_{ES-CS}.)
"""
from common import h, xor, rnd, AuthError, ID_BYTES, HASH_BYTES
import bakmm_iod as B

DELTA_T = B.DELTA_T


class LiteralDrone(B.Drone):
    """DE that derives SK with the concatenation order printed in AKDDE3 / Table 5."""

    def finish(self, msg2):
        m = self.mem
        if abs(msg2["T2"] - self.clock.now()) > DELTA_T:
            raise AuthError("DE: stale T2")
        T2 = msg2["T2"]
        Bv = xor(msg2["M3"], h(m["RID"], m["MS"], T2))
        SK = h(self.A, Bv, m["RID"], self.T1, T2, m["MS"])          # printed DE-side order
        if h(SK, self.T1, T2, m["RID"]) != msg2["M4"]:
            raise AuthError("DE: M4 mismatch")
        m["TID"] = xor(msg2["M5"], h(self.A, m["RID"], T2)[:ID_BYTES])
        self.session_key = SK
        T3 = self.clock.now()
        return dict(M6=h(SK, T3), T3=T3)


# --------------------------------------------------------------------------- ES <-> CS
class RAKM:
    """Credentials for one ES_j <-> CS_k pair (RSES1/RSCS1)."""

    @staticmethod
    def register(clock):
        es = dict(TIN=rnd(ID_BYTES), RID=rnd(ID_BYTES), TC=rnd(HASH_BYTES), MS=rnd(HASH_BYTES))
        cs = dict(TC=rnd(HASH_BYTES), db={es["TIN"]: dict(RID=es["RID"], MS=es["MS"])})
        return es, cs


class ESInitiator:
    def __init__(self, cred, clock, E1=False, E4=False):
        self.c, self.clock, self.E1, self.E4 = dict(cred), clock, E1, E4
        self.session_key = None

    def akdec1(self):
        c = self.c
        self.TS1, self.RS1 = self.clock.now(), rnd()
        self.X1 = h(self.RS1, c["TC"], c["MS"], self.TS1)                            # h(RS1||TC||MS||TS1)
        inner_m1 = h(c["TC"], self.RS1, c["MS"], self.TS1) if self.E1 else self.X1   # printed m1 order
        m1 = xor(inner_m1, h(c["RID"], c["MS"], self.TS1))
        m2 = h(self.X1, c["RID"], c["MS"], self.TS1)
        return dict(TIN=c["TIN"], m1=m1, m2=m2, TS1=self.TS1)

    def akdec3(self, msg2):
        c = self.c
        if abs(msg2["TS2"] - self.clock.now()) > DELTA_T:
            raise AuthError("ES: stale TS2")
        TS2 = msg2["TS2"]
        Y = xor(msg2["m3"], h(c["RID"], c["MS"], self.TS1, TS2))
        SK = h(Y, self.X1, c["RID"], c["MS"], self.TS1, TS2)
        if h(SK, c["RID"], c["MS"], TS2) != msg2["m4"]:
            raise AuthError("ES: m4 mismatch")
        if self.E4:
            # printed: h(RID || h(RS2 || TC_ES || MS || TS1) || TS2).  RS2 never leaves the CS
            # (only h(RS2||TC_CS||MS||TS2) is recoverable from m3), so the ES has to use a value
            # it does not know; a fresh random stand-in models that.
            mask = h(c["RID"], h(rnd(), c["TC"], c["MS"], self.TS1), TS2)
        else:
            mask = h(c["RID"], self.X1, TS2)
        c["TIN"] = xor(msg2["m5"], mask[:ID_BYTES])
        self.session_key = SK
        TS3 = self.clock.now()
        return dict(m6=h(SK, TS3), TS3=TS3)


class CSResponder:
    def __init__(self, cred, clock):
        self.TC, self.db, self.clock = cred["TC"], dict(cred["db"]), clock
        self.pending, self.session_key = None, None

    def akdec2(self, msg1):
        if abs(msg1["TS1"] - self.clock.now()) > DELTA_T:
            raise AuthError("CS: stale TS1")
        rec = self.db.get(msg1["TIN"])
        if rec is None:
            raise AuthError("CS: unknown TIN (desynchronised)")
        RID, MS, TS1 = rec["RID"], rec["MS"], msg1["TS1"]
        X1 = xor(msg1["m1"], h(RID, MS, TS1))           # CS believes this is h(RS1||TC_ES||MS||TS1)
        if h(X1, RID, MS, TS1) != msg1["m2"]:
            raise AuthError("CS: m2 mismatch")
        TS2, RS2 = self.clock.now(), rnd()
        Y = h(RS2, self.TC, MS, TS2)
        m3 = xor(Y, h(RID, MS, TS1, TS2))
        SK = h(Y, X1, RID, MS, TS1, TS2)
        m4 = h(SK, RID, MS, TS2)
        TIN_new = rnd(ID_BYTES)
        m5 = xor(TIN_new, h(RID, X1, TS2)[:ID_BYTES])
        self.pending = dict(old=msg1["TIN"], new=TIN_new, SK=SK, rec=rec)
        return dict(m3=m3, m4=m4, m5=m5, TS2=TS2)

    def akdec4(self, msg3):
        if abs(msg3["TS3"] - self.clock.now()) > DELTA_T:
            raise AuthError("CS: stale TS3")
        p = self.pending
        if h(p["SK"], msg3["TS3"]) != msg3["m6"]:
            raise AuthError("CS: m6 mismatch")
        self.db.pop(p["old"], None)
        self.db[p["new"]] = p["rec"]
        self.session_key = p["SK"]
        return p["SK"]


def run_km(es, cs, clock):
    """One ES<->CS key-management session. Returns (SK_ES, SK_CS)."""
    m1 = es.akdec1(); clock.advance()
    m2 = cs.akdec2(m1); clock.advance()
    m3 = es.akdec3(m2); clock.advance()
    return es.session_key, cs.akdec4(m3)
