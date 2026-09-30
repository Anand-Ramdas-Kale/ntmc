"""Ablation: switch off one modification (M1-M6) or one review fix (F2-F4) at a time and re-run the
attacks that each one is supposed to stop.  A cell is RE-OPENED when an attack that FSL-AKE-IoD v2
resists succeeds (or gets worse) once the switch is off.

Run:  python ablation.py
"""
import attacks_fslake as A
import cost
import fslake as F

VARIANTS = [
    ("v2 (all on)", F.V2),
    ("M1 off: no key evolution", F.without(M1_key_evolution=False)),
    ("M2 off: static TID", F.without(M2_tid_update=False)),
    ("M3 off: single record", F.without(M3_dual_record=False)),
    ("M4 off: no replay cache", F.without(M4_replay_cache=False)),
    ("M5 off: plain K in ES DB", F.without(M5_masked_verifier=False)),
    ("M6 off: add MSG3", F.without(M6_two_message=False)),
    ("F2 off: cache expiry from receive time", F.without(F2_cache_expiry_from_T1=False)),
    ("F3 off: one old + one cur (v1 records)", F.without(F3_candidate_set=False, F4_retry_gap=False)),
    ("F4 off: no retry gap", F.without(F4_retry_gap=False)),
]

ATTACKS = [
    A.capture_past_keys, A.capture_link_tids, A.anonymity_passive, A.stolen_db_without_X,
    A.es_compromise_with_X, A.desync_drop_once, A.desync_reordered_retry, A.desync_candidate_eviction,
    A.replay_inside, A.replay_with_clock_skew, A.modify_fields, A.drone_impersonation,
]

RANK = {A.RES: 0, A.NA: 0, A.PART: 1, A.SUCC: 2}


def _worse(base, r):
    if RANK[r.outcome] > RANK[base.outcome]:
        return True
    if r.attack.startswith("ES compromise"):
        return r.data.get("past_exposed", 0) > base.data.get("past_exposed", 0)
    if r.attack.startswith("anonymity"):
        return r.data.get(0, 0) > base.data.get(0, 0)
    return False


def run():
    base = {a.__name__: a(A.FSLv2Impl(F.V2, "v2")) for a in ATTACKS}
    table = {}
    for label, cfg in VARIANTS:
        impl = A.FSLv2Impl(cfg, label)
        row = {}
        for a in ATTACKS:
            r = base[a.__name__] if cfg == F.V2 else a(impl)
            row[a.__name__] = (r, cfg != F.V2 and _worse(base[a.__name__], r))
        c = cost.count_fsl(cfg, label)
        table[label] = dict(results=row, cost=c)
    return table


def reopened(table):
    return {label: [r.attack for r, worse in v["results"].values() if worse] for label, v in table.items()}


if __name__ == "__main__":
    T = run()
    for label, v in T.items():
        c = v["cost"]
        re = [f"{r.attack} -> {r.outcome}" for r, worse in v["results"].values() if worse]
        print(f"{label:40s} DE {c['de']} ES {c['es']} msgs {c['msgs']} bits {c['bits']:5d} | re-opened: "
              f"{re if re else 'nothing'}")
        if label.startswith("M6"):
            ec = v["results"]["es_compromise_with_X"][0]
            print(f"{'':40s} note: {ec.reason}")
