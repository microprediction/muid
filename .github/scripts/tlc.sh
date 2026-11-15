#!/usr/bin/env bash
# SPEC §12: the TLA+ models in model/tla, checked by TLC. The tools are fetched at a pinned release and checked
# against the SHA-256 recorded when they were first reviewed (the release publishes no digest), then each model
# configuration is run: those listed as passing must find no error, and each negative control must report the
# violation it names, so a model that stopped checking anything would fail here.
#   tlc.sh                  the configurations run on every pull request (minutes)
#   tlc.sh long             those too large for that, exhaustively (about an hour), stopped if the disk runs low
#   tlc.sh sample SECONDS   those too large to finish: random walks for SECONDS each, a new seed each time. No
#                           violation found is not a result about the bound; a violation is, and prints its trace.
set -euo pipefail
VERSION=v1.7.4
SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
# TLA_JAR names a copy already downloaded (a local run); it is checked against the same digest. TLC_WORKERS limits its threads.
JAR="${TLA_JAR:-${RUNNER_TEMP:-/tmp}/tla2tools-$VERSION.jar}"
[ -n "${TLA_JAR:-}" ] || curl -fsSL -o "$JAR" "https://github.com/tlaplus/tlaplus/releases/download/$VERSION/tla2tools.jar"
echo "$SHA256  $JAR" | shasum -a 256 -c -
cd model/tla
status=0
MODE="${1:-each}"
TMP="${RUNNER_TEMP:-/tmp}"
# model config expectation (pass, or the property a negative control must violate)
each () {
  while read -r model config expect; do
    [ -z "$model" ] && continue
    out=$(java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers "${TLC_WORKERS:-auto}" -nowarning -metadir "$TMP/tlc-$config" -config "$config.cfg" "$model.tla" 2>&1) && code=0 || code=$?
    summary=$(printf '%s\n' "$out" | grep -E 'violated|No error has been found|states generated|Finished in' | tail -4)
    if [ "$expect" = pass ]; then
      if [ "$code" -ne 0 ]; then echo "::error::$config: expected no error"; printf '%s\n' "$out" | tail -60; status=1; fi
    elif ! printf '%s\n' "$out" | grep -q "$expect is violated"; then
      echo "::error::$config: expected $expect to be violated (a negative control)"; printf '%s\n' "$out" | tail -40; status=1
    fi
    echo "$config ($expect): $summary"
  done
}
# Random walks for $1 seconds over each configuration: any violation, or any other error, fails. The last is a
# negative control the walks must break (they did in seconds when tried; a walk stops at its first violation).
sample () {
  while read -r model config expect; do
    [ -z "$model" ] && continue
    out=$(java -XX:+UseParallelGC -Dtlc2.TLC.stopAfter="$1" -cp "$JAR" tlc2.TLC -simulate -depth 80 -workers "${TLC_WORKERS:-auto}" -nowarning -metadir "$TMP/tlc-$config" -config "$config.cfg" "$model.tla" 2>&1) && code=0 || code=$?
    if [ "$expect" != sample ]; then
      if ! printf '%s\n' "$out" | grep -q "$expect is violated"; then
        echo "::error::$config: no walk broke $expect (a negative control: the walks may no longer check anything)"; printf '%s\n' "$out" | tail -20; status=1
      fi
    elif [ "$code" -ne 0 ] || printf '%s\n' "$out" | grep -qE 'is violated|^Error:'; then
      echo "::error::$config: a random walk found an error (the trace follows)"; printf '%s\n' "$out" | tail -200; status=1
    fi
    echo "$config ($expect, ${1}s): $(printf '%s\n' "$out" | grep -oE 'with seed -?[0-9]+|[0-9]+ states checked|Invariant \w+ is violated' | tr '\n' ' ')"
  done
}
case "$MODE" in
long)
  # TLC keeps its queue of states on disk. Stop it, as a failure, before the runner's disk is full.
  ( while sleep 30; do
      free=$(df -Pk "$TMP" | awk 'NR==2 { print $4 }')
      if [ "$free" -lt 2097152 ]; then echo "::error::under 2 GB of disk left: TLC stopped"; pkill -f tlc2.TLC; exit; fi
    done ) &
  watch=$!
  each <<'MODELS'
MCIdPage IdPageTwoTabs pass
MODELS
  kill "$watch" 2>/dev/null || true
  ;;
sample)
  case "${2:-}" in ''|0*|*[!0-9]*) echo "sample needs a number of seconds"; exit 1;; esac
  sample "$2" <<'MODELS'
MCIdPage IdPageWide sample
MCIdPage IdPageTwoAgents sample
MCIdPage IdPageTwoAuds sample
MCIdPage IdPageNoGuardReplies NoRevival
MODELS
  ;;
each)
  each <<'MODELS'
MCAdapter Adapter pass
MCAdapter AdapterGraceTooShort AtMostOnce
MCAdapter AdapterNoCommitCheck AtMostOnce
MCAdapter AdapterNoDelegationCheck NoExpiredAuthorizationAtCommit
MCAdapter AdapterNoHeadCheck NoExpiredAuthorizationAtCommit
MCAdapter AdapterNoKeyCheck NoExpiredAuthorizationAtCommit
MCAdapter AdapterBoundTighter FreshnessBound
MCAdapter AdapterDishonestWitness pass
MCAdapter AdapterNoRevocationMemory NoRevival
MCIdPage IdPage pass
MCIdPage IdPageNoTransactional NoLostUpdate
MCIdPage IdPageNoFreshWrite NoResurrection
MCIdPage IdPageNoForgetExact NoLostUpdate
MCIdPage IdPageNoCheckReviewed ShownIsSaved
MCIdPage IdPageNoCheckChanged ReviewedStateIsCurrent
MCIdPage IdPageNoCompareRev ReviewedStateIsCurrent
MCIdPage IdPageNoCheckExpiry Unexpired
MCIdPage IdPageNoGuardReplies NoRevival
MCIdPage IdPageNoPublishAfterCommit SavedBeforeHandover
MCIdPage IdPageNoWithdrawOnChange ShownIsSaved
MCIdPage IdPageNoViewFromStore ViewHonest
IdRoot IdRoot pass
IdRoot IdRootNoCas NeverOverwritten
IdRoot IdRootLoserRegisters JoiningNeverRegistered
IdRoot IdRootMarksHeld MarkedIsTaken
IdRoot IdRootMarksHeldMember MemberIsCosigned
WitnessOutbox WitnessOutbox pass
WitnessOutbox WitnessOutboxNoSettleFirst NoRival
WitnessOutbox WitnessOutboxNoAppendOutbox HeldIsLogged
WitnessOutbox WitnessOutboxNoStageFirst NoRival
WitnessOutbox WitnessOutboxNoAnswerAfterLogged ServedIsLogged
WitnessOutbox WitnessOutboxNoServeSettled HeldIsLogged
WitnessOutbox WitnessOutboxNoSerialised NoRival
MODELS
  ;;
*) echo "unknown mode $MODE"; exit 1;;
esac
exit $status
