#!/usr/bin/env bash
# SPEC §12: the TLA+ models in model/tla, checked by TLC. The tools are fetched at a pinned release and checked
# against the SHA-256 recorded when they were first reviewed (the release publishes no digest), then each model
# configuration is run: those listed as passing must find no error, and each negative control must report the
# violation it names, so a model that stopped checking anything would fail here.
set -euo pipefail
VERSION=v1.7.4
SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
# TLA_JAR names a copy already downloaded (a local run); it is checked against the same digest.
JAR="${TLA_JAR:-${RUNNER_TEMP:-/tmp}/tla2tools-$VERSION.jar}"
[ -n "${TLA_JAR:-}" ] || curl -fsSL -o "$JAR" "https://github.com/tlaplus/tlaplus/releases/download/$VERSION/tla2tools.jar"
echo "$SHA256  $JAR" | shasum -a 256 -c -
cd model/tla
status=0
# model config expectation (pass, or the property a negative control must violate)
while read -r model config expect; do
  [ -z "$model" ] && continue
  out=$(java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -nowarning -metadir "${RUNNER_TEMP:-/tmp}/tlc-$config" -config "$config.cfg" "$model.tla" 2>&1) && code=0 || code=$?
  summary=$(printf '%s\n' "$out" | grep -E 'violated|No error has been found|states generated|Finished in' | tail -4)
  if [ "$expect" = pass ]; then
    if [ "$code" -ne 0 ]; then echo "::error::$config: expected no error"; printf '%s\n' "$out" | tail -60; status=1; fi
  elif ! printf '%s\n' "$out" | grep -q "$expect is violated"; then
    echo "::error::$config: expected $expect to be violated (a negative control)"; printf '%s\n' "$out" | tail -40; status=1
  fi
  echo "$config ($expect): $summary"
done <<'MODELS'
MCAdapter Adapter pass
MCAdapter AdapterGraceTooShort AtMostOnce
MCAdapter AdapterNoCommitCheck AtMostOnce
MCAdapter AdapterBoundTighter FreshnessBound
MODELS
exit $status
