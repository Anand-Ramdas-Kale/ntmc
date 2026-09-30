# PoC code: cryptanalysis of BAKMM-IoD and the proposed FSL-AKE-IoD

Python 3.8+, needs only `matplotlib` (for the figures). SHA-256 comes from `hashlib`.

| File | Purpose |
|---|---|
| `common.py` | h(.) = SHA-256 over a length-prefixed concatenation, XOR, a simulated clock, message-size accounting and a hash-operation counter |
| `bakmm_iod.py` | Faithful implementation of BAKMM-IoD DE<->ES authentication (Wazid et al., JSA 160, 2025, Table 5) |
| `attacks_bakmm.py` | 4 working attacks: drone capture (all past/future SKs and the TID chain), stolen verifier, de-synchronisation, replay inside ΔT |
| `proposed_fslake.py` | The proposed FSL-AKE-IoD protocol |
| `attacks_proposed.py` | The same 4 attacks run against the proposal (all fail), plus a 1000-session correctness test |
| `benchmark.py` | Counts hash operations by instrumentation, measures time, and produces `results.csv`, `fig_comm_cost.png` and `fig_comp_cost.png` |
| `architecture.py` | Draws `fig_architecture.png` |
| `fslake_iod.spdl` | Scyther model of the proposal. It was **not run in the drafting environment**: open it in Scyther, run Verify, and paste the screenshot into the paper |

```
python3 attacks_bakmm.py      # all attacks -> True
python3 attacks_proposed.py   # all resisted -> True
python3 benchmark.py          # 8/8 vs 5/7 hashes, 1792 vs 1056 bits
python3 architecture.py
```

The instrumented hash counts for BAKMM-IoD (8 on the drone, 8 on the server) match the paper's own Table 8. That is a check that the re-implementation is faithful.
