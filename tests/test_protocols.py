"""One-command regression suite for the BAKMM-IoD cryptanalysis and the FSL-AKE-IoD review.

    python -m pytest tests -q

Covers: correctness of every protocol variant, the expected outcome of every attack against every
protocol (BAKMM-IoD under both ES update policies, FSL-AKE-IoD v1 as drafted, FSL-AKE-IoD v2),
the Phase 1 verdicts, the ablation study, and the instrumented hash / bit counts.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "proposed", "code"))

import ablation                      # noqa: E402
import attacks_bakmm_ext as X        # noqa: E402
import attacks_fslake as A           # noqa: E402
import bakmm_iod as B                # noqa: E402
import bakmm_literal as L            # noqa: E402
import cost                          # noqa: E402
import fslake as F                   # noqa: E402
import proposed_fslake as P1         # noqa: E402
from common import AuthError, Clock  # noqa: E402

S, R, P, N = A.SUCC, A.RES, A.PART, A.NA
COLUMNS = ["BAKMM", "BAKMM[on_send]", "FSL-v1", "FSL-v2"]

# (BAKMM on_confirm, BAKMM on_send, FSL v1, FSL v2) - outcome for the ADVERSARY
EXPECTED = {
    "replay_inside":              (S, R, R, R),
    "replay_outside":             (R, R, R, R),
    "replay_after_resync":        (N, N, R, R),
    "replay_with_clock_skew":     (R, R, S, R),
    "reboot_replay":              (N, N, S, R),
    "modify_fields":              (S, S, R, R),
    "reflection":                 (R, R, R, R),
    "interleave":                 (R, R, R, R),
    "drone_impersonation":        (R, R, R, R),
    "es_impersonation":           (R, R, R, R),
    "kci_after_capture":          (S, S, S, S),
    "capture_past_keys":          (S, S, R, R),
    "capture_future_keys":        (S, S, S, S),
    "capture_link_tids":          (S, S, P, P),
    "stolen_db_without_X":        (S, S, R, R),
    "es_compromise_with_X":       (S, S, P, P),
    "esl_ephemerals_only":        (R, R, R, R),
    "reveal_sk_get_k":            (R, R, R, R),
    "reveal_state_mid_session":   (R, R, R, R),
    "known_session_key":          (R, R, R, R),
    "desync_drop_once":           (S, S, R, R),
    "desync_drop_repeated":       (R, S, R, R),
    "desync_reordered_retry":     (R, R, S, R),
    "desync_candidate_eviction":  (R, R, S, R),
    "cross_es":                   (P, P, P, P),
    "dos_costs":                  (R, R, R, R),
    "delta_t_edges":              (P, P, P, P),
    "insider_ra":                 (P, P, P, P),
    "dynamic_add_default_enroll": (R, R, S, R),
    "revocation":                 (N, N, S, R),
    "tid_collision":              (N, N, S, R),
    "anonymity_passive":          (P, P, P, P),
}


def test_every_attack_has_an_expectation():
    assert {a.__name__ for a in A.ATTACKS} == set(EXPECTED)


# --------------------------------------------------------------------------- correctness
def test_bakmm_correct_both_policies():
    for pol in ("on_confirm", "on_send"):
        c = Clock(); _, es, de = B.setup(c, pol)
        for _ in range(300):
            _, a, b = B.run_session(de, es, c); assert a is not None and a == b; c.advance(10)


def test_bakmm_printed_sk_order_never_agrees():
    assert X.a0_literal_sk_order(200)["evidence"].startswith("0/200")


@pytest.mark.parametrize("cfg", [F.V2, F.without(M6_two_message=False), F.without(retry_pseudonyms=3),
                                 F.V1_EQUIVALENT], ids=["v2", "v2-3msg", "v2-rp3", "v1-equiv"])
def test_fslake_correct_1000_sessions_with_drops(cfg):
    c = Clock(); _, es, de = F.setup(c, cfg)
    ok = expected = 0
    for i in range(1000):
        drop = "MSG2" if i % 7 == 3 else None
        _, a, b = F.run_session(de, es, c, drop=drop)
        if drop is None:
            expected += 1; ok += a is not None and a == b
        c.advance(10)
    assert ok == expected


def test_fslake_v1_correct_1000_sessions():
    c = Clock(); _, es, de = P1.setup(c)
    for _ in range(1000):
        _, a, b = P1.run_session(de, es, c); assert a == b; c.advance(10)


def test_fslake_es_cs_and_multi_drone():
    c = Clock(); _, es, ds = F.setup(c, n=5)
    for _ in range(20):
        for d in ds:
            _, a, b = F.run_session(d, es, c); assert a == b; c.advance(5)


def test_bakmm_es_cs_errata():
    ev = X.e_escs()["evidence"]
    assert "corrected: s1 agree=True, s2 agree=True" in ev
    assert "E1 printed m1/m2 order: s1 fails (CS: m2 mismatch)" in ev
    assert "E4 printed TIN recovery with RS2: s1 agree=True, s2 fails" in ev


# --------------------------------------------------------------------------- Phase 1 verdicts
def test_phase1_verdicts():
    v = {r["id"]: r for r in X.run_all()}
    assert v["A1"]["verdict"] == "CONFIRMED" and "5/5 past" in v["A1"]["evidence"]
    assert v["A2"]["verdict"] == "CONDITIONAL" and "3/3 drones impersonated" in v["A2"]["evidence"]
    assert "on_confirm/drop MSG3: LOCKED OUT" in v["A3"]["evidence"]
    assert "on_send/drop MSG2: LOCKED OUT" in v["A3"]["evidence"]
    assert "on_confirm: replay accepted=True" in v["A4"]["evidence"]
    assert "on_send: replay accepted=False" in v["A4"]["evidence"]
    assert v["A5"]["evidence"].count("locked out afterwards=True") == 2
    assert "sum=1792" in v["C"]["evidence"] and "1696" in v["C"]["evidence"]


# --------------------------------------------------------------------------- attack matrix
@pytest.fixture(scope="module")
def impl_by_name():
    return {i.name: i for i in A.impls()}


@pytest.mark.parametrize("attack", A.ATTACKS, ids=lambda f: f.__name__)
def test_attack_outcomes(attack, impl_by_name):
    for col, want in zip(COLUMNS, EXPECTED[attack.__name__]):
        got = attack(impl_by_name[col])
        assert got.outcome == want, f"{attack.__name__} vs {col}: {got.outcome} ({got.reason})"


def test_es_compromise_quantified():
    r = A.es_compromise_with_X(A.FSLv2Impl())
    assert r.data == dict(past_exposed=3, past_total=15, future_exposed=3)
    r3 = A.es_compromise_with_X(A.FSLv2Impl(F.without(M6_two_message=False), "3msg"))
    assert r3.data["past_exposed"] == 0


def test_retry_pseudonyms_remove_retry_linkability():
    r = A.anonymity_passive(A.FSLv2Impl(F.without(retry_pseudonyms=3), "rp3"))
    assert r.outcome == R


def test_reboot_quiet_period_then_service_resumes():
    c = Clock(); _, es, de = F.setup(c)
    F.run_session(de, es, c); es.reboot()
    with pytest.raises(AuthError):
        es.respond(de.start())
    c.advance(2 * F.DELTA_T + 1)
    _, a, b = F.run_session(de, es, c)
    assert a == b


# --------------------------------------------------------------------------- ablation
def test_ablation_every_switch():
    T = ablation.run()
    re = ablation.reopened(T)
    assert re["v2 (all on)"] == []
    assert "capture: past SKs (forward secrecy)" in re["M1 off: no key evolution"]
    assert "anonymity: passive linking" in re["M2 off: static TID"]
    assert re["M3 off: single record"] == ["de-sync: drop one message"]
    assert "replay MSG1 inside dT" in re["M4 off: no replay cache"]
    assert re["M5 off: plain K in ES DB"] == ["stolen ES DB (no X_ES)"]
    assert re["M6 off: add MSG3"] == []                       # M6 is a cost optimisation only
    assert re["F2 off: cache expiry from receive time"] == ["replay + clock skew (+1 s)"]
    assert "de-sync: reordered retry (2 records)" in re["F3 off: one old + one cur (v1 records)"]
    assert re["F4 off: no retry gap"] == ["de-sync: 6 withheld retries (eviction)"]


# --------------------------------------------------------------------------- cost
def test_hash_counts_and_bits():
    b, f, v1 = cost.count_bakmm(), cost.count_fsl(), cost.count_fsl_v1()
    assert (b["de"], b["es"], b["msgs"], b["bits"]) == (8, 8, 3, 1792)
    assert b["per_msg"] == [704, 800, 288] and b["bits_actual"] == 1696
    assert (f["de"], f["es"], f["msgs"], f["bits"]) == (5, 7, 2, 1056)
    assert f["per_msg"] == [608, 448]
    assert (v1["de"], v1["es"], v1["bits"]) == (5, 7, 1056)
    m6 = cost.count_fsl(F.without(M6_two_message=False))
    assert (m6["de"], m6["es"], m6["msgs"], m6["bits"]) == (6, 8, 3, 1344)


def test_not_strictly_cheaper_on_server():
    me, ties = cost.strictly_cheaper(cost.comparison_rows())
    assert me["drone_ms"] == pytest.approx(5 * 0.309) and me["server_ms"] == pytest.approx(7 * 0.055)
    assert ties["drone_ms"] == [] and ties["bits"] == [] and ties["msgs"] == []
    assert [s for s, _ in ties["server_ms"]] == ["Algarni and Jan"]


def test_tid_collision_bound():
    assert cost.tid_collision_bound()["bound"] < 1e-23
