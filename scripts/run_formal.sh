#!/usr/bin/env bash
# Runs every Scyther and ProVerif model and saves the results.
#   SCYTHER=/path/to/scyther-linux  PROVERIF=proverif  bash scripts/run_formal.sh
# Text results go to formal_results/, claim-table PNGs to images/ (via proposed/code/formal_report.py),
# and attack graphs (when a claim fails) to images/<model>_attack.svg if Graphviz `dot` is present.
set -u
cd "$(dirname "$0")/.."
SCYTHER=${SCYTHER:-$(command -v scyther-linux || command -v scyther || true)}
PROVERIF=${PROVERIF:-$(command -v proverif || true)}
mkdir -p formal_results images

MODELS="bakmm_auth.spdl bakmm_key_mgmt.spdl proposed/code/fslake_iod.spdl fslake_auth.spdl fslake_key_mgmt.spdl \
        bakmm_auth_compromise.spdl bakmm_auth_compromise_xorfun.spdl \
        fslake_auth_compromise.spdl fslake_auth_compromise_control.spdl \
        models/02_authentication.spdl models/03_key_management.spdl"

if [ -n "$SCYTHER" ]; then
  for m in $MODELS; do
    base=$(basename "$m" .spdl)
    echo "== Scyther $m"
    "$SCYTHER" --max-runs=4 "$m" > "formal_results/$base.txt" 2>&1
    "$SCYTHER" --max-runs=4 --dot-output --output="formal_results/$base.dot" "$m" > /dev/null 2>&1 || true
    if command -v dot > /dev/null && [ -s "formal_results/$base.dot" ]; then
      dot -Tsvg "formal_results/$base.dot" -o "images/${base}_attack.svg" || true
    fi
    python proposed/code/formal_report.py "formal_results/$base.txt" "images/scyther_$base.png"
  done
else
  echo "NOT RUN: Scyther not found (set SCYTHER=/path/to/scyther-linux)"
fi

if [ -n "$PROVERIF" ]; then
  for m in proverif/*.pv; do
    base=$(basename "$m" .pv)
    echo "== ProVerif $m"
    "$PROVERIF" "$m" > "formal_results/$base.txt" 2>&1
    grep -E "^RESULT" "formal_results/$base.txt"
  done
else
  echo "NOT RUN: ProVerif not found (opam install proverif)"
fi
