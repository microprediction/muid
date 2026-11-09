#!/usr/bin/env bash
# SPEC §12: the Tamarin theories in model/tamarin, proved, and their negative controls, each a one-line edit of a copy
# (as the broken twins are of the code): a theory's lemmas must all verify, and each control must give the result
# written beside it, so that a lemma that had become a tautology would fail here.
set -euo pipefail
cd model/tamarin
work=$(mktemp -d)
status=0
# lemma results of one theory file: "name result" lines
results () { tamarin-prover --prove "$1" 2>&1 | sed -n '/summary of summaries/,$p' | sed -nE 's/^ +([a-z_]+) \((all-traces|exists-trace)\): ([a-z]+).*/\1 \3/p'; }
expect () { # file lemma result
  got=$(results "$1" | awk -v l="$2" '$1 == l { print $2 }')
  if [ "$got" != "$3" ]; then echo "::error::$1: $2 is ${got:-missing}, expected $3"; status=1; else echo "$1: $2 $3"; fi
}
# Claims.spthy: every lemma verifies.
for lemma in executable delegation_authentic claim_authentic consent audience; do expect Claims.spthy "$lemma" verified; done
# Controls: consent has two defences, each enough alone; without both it fails.
sed "/Eq(verify(cs, <'accept', h(d)>, p), true),/d" Claims.spthy > "$work/NoConsent.spthy"
sed -e "s/<'claim', h(d), <A, \$path>>/<'claim', <A, \$path>>/" -e "s/<'claim', h(d), req>/<'claim', req>/" Claims.spthy > "$work/Unbound.spthy"
sed -e "s/<'claim', h(d), <A, \$path>>/<'claim', <A, \$path>>/" -e "s/<'claim', h(d), req>/<'claim', req>/" "$work/NoConsent.spthy" > "$work/Neither.spthy"
for f in NoConsent Unbound Neither; do
  if cmp -s Claims.spthy "$work/$f.spthy"; then echo "::error::control $f: the edit no longer applies"; status=1; fi
done
expect "$work/NoConsent.spthy" consent verified
expect "$work/Unbound.spthy" consent verified
expect "$work/Neither.spthy" consent falsified
exit $status
