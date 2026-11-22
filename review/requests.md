# Review requests

Specific things a maintainer has asked to have looked at. A scheduled review takes the first open request here
before anything else; [`README.md`](README.md) says how what is found is reported. Answer in an issue titled
`[automated review] request Rn: <one line>`, also when the answer is that nothing is wrong: a request is a question,
and silence does not answer it.

A request too large for one run says how it is divided and lists the parts already answered: take the next part.

A request is closed here, with the issue that answered it, by whoever asked.

## Open

- **R1. The scenarios themselves.** `review/scenarios.md` was written from the spec and the code as known, not each
  claim checked against the source. Read one group against the files its heading names and list every claim that is
  wrong about what the system does or should do, cannot arise, or duplicates another.
  One group per run; take the first group not listed here as done.
  Done: *Relying parties and the demo* (133–142), answered in #111 and corrected; *Verifier and signed heads*
  (1–18), answered in #115 and corrected; *Encoding and envelope* (19–32), answered in #119 and corrected;
  *Roots, passkey assertions* (33–46), answered in #122 and corrected; *Ed25519 delegate keys and delegations*
  (47–58), answered in #128 and corrected; *Membership: adding roots, contests, settlement* (59–73), answered in
  #130 and #132, corrected, and a witness defect fixed; *Recovery* (74–94), answered in #137, #141, #143, #146,
  #147, #149 and #150, corrected, and witness defects fixed; *The id page* (95–112), answered in #154 and #158 and
  corrected; *The page's store* (113–116), answered in #161 and corrected; *The witness service* (117–132),
  answered in #166, with inaccurate claims 121, 126 and 132 corrected and the witness defect behind 127 fixed; *Receipts and attestations* (143–145),
  answered in #168 with no discrepancy or missing regression test found; *Tests, models and the build* (146–160),
  answered in #171, #173, #175, #177, #179, #180, #182, #184, #186 and #188, corrected, with the model and
  Tamarin scope narrowed, the npm pack contents and the core bans guarded, and the guards strengthened.
- **R2. Recovery at the id page.** `id/page.js` from "R11" onwards, with `id/records.js`: designating parties, a
  party's card and proof, the request to recover, the rescue, the notice and its cancel. Is there any path on which
  a passkey signs something other than what its panel showed, or on which the owner is not told of a recovery under
  way? This is the newest code in the page. Answered so far: #153 (an older notice answer hid a newer one), fixed; #191, no
  finding; #192 (a late answer to a signed record sent for a withdrawn review was shown), fixed.
- **R3. Tests that wait for nothing.** `tests/id/P2-page.test.mjs` had checks that something did not happen which
  ran before it could have (now waiting on `idle`). Are there any left, there or in `tests/id/P4-recovery.test.mjs`
  and `tests/witness/`, including fixed waits (`waitForTimeout`) that a slow machine would outrun?
- **R4. The mutation split.** `tests/mutation-plan.mjs`, `tests/guards/mutation-coverage.test.mjs` and the
  `stryker.id-page-*.config.json` files divide `id/page.js` by line range. Can a line be left in no part, or the
  guard pass while one is?

## Closed

None yet.
