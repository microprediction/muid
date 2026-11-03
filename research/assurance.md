# Test-first assurance

## Findings

### Mutation testing

1. StrykerJS runs `node --test` suites through `@stryker-mutator/tap-runner` (`"testRunner": "tap"`, `tap.testFiles`,
   `tap.nodeArgs`, `tap.forceBail`). Limitations: no per-test reporting (each test file counts as one test), one process
   per test file ("can be slow"), coverage per test file, static mutants not detected.
   https://stryker-mutator.io/docs/stryker-js/tap-runner/
2. Stryker `thresholds` default to `{high: 80, low: 60, break: null}`; a score below `break` exits with code 1;
   `coverageAnalysis` is `off`/`all`/`perTest`; `incremental: true` caches results; `mutator.excludedMutations` takes
   mutator names. https://stryker-mutator.io/docs/stryker-js/configuration/
3. Just et al. (FSE 2014), 357 real faults in 5 programs: a "statistically significant correlation between mutant
   detection and real fault detection, independently of code coverage"; 73% of faults coupled to mutants; about 17% not
   coupled to any mutant. https://homes.cs.washington.edu/%7Emernst/pubs/mutation-effectiveness-fse2014.pdf
4. Trail of Bits uses mutation testing in its security reviews because "coverage metrics tell you whether code was
   executed during testing, not whether it was actually tested for correctness"; `necessist` deletes test statements
   and reports tests that still pass. https://blog.trailofbits.com/2025/09/18/use-mutation-testing-to-find-the-bugs-your-tests-dont-catch/ ;
   https://trailofbits.com/skills/genotoxic/
5. Mutation frameworks often run only tests in the mutated code's package, so some mutants are wrongly reported as
   uncovered. https://trailofbits.com/skills/vector-forge/

### Property testing and fuzzing

6. fast-check has found serialiser, round-trip and prototype-key bugs: js-yaml (`0b-1010`), eemeli/yaml round-trip
   spacing, query-string `[a,null,b]` → `[null,b]`, javascript-stringify `-0` → `"0"`, jsonwebtoken throwing on
   `valueOf`/`__proto__` keys, non-BMP handling in left-pad, and most of lodash's prototype-poisoning CVEs.
   https://fast-check.dev/docs/introduction/track-record/
7. Jazzer.js (libFuzzer-based, in-process, coverage-guided fuzzer for Node) is not archived, released v4.0.0 on
   2026-04-15 and had commits on 2026-11-02; Snyk advisor pages calling it "Inactive / deprecated" reflect the earlier
   gap after v2.1.0 (October 2023). https://github.com/CodeIntelligenceTesting/jazzer.js ;
   https://github.com/CodeIntelligenceTesting/jazzer.js/releases ; https://snyk.io/advisor/npm-package/@jazzer.js/fuzzer

### Known-answer vectors

8. Wycheproof lives at C2SP/wycheproof (`testvectors_v1/`, schemas in `schemas/`, legacy data at tag
   `wycheproof-v0-vectors`). `ed25519_test.json`: 210 tests (117 valid, 64 invalid, 29 acceptable).
   `ecdsa_secp256r1_sha256_test.json` (DER): 484 tests (174 valid, 310 invalid).
   `ecdsa_secp256r1_sha256_p1363_test.json`: 262 tests (173 valid, 89 invalid). https://github.com/C2SP/wycheproof ;
   https://github.com/C2SP/wycheproof/tree/main/testvectors_v1
9. All 29 Ed25519 "acceptable" vectors are small-order (8) or mixed-order (21) public keys that implementations "may
   reject … under a stricter public-key policy". https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/ed25519_test.json
10. ed25519-speccheck: 12 edge-case vectors (eprint 2020/1244). https://github.com/novifinancial/ed25519-speccheck ;
    https://eprint.iacr.org/2020/1244
11. RFC 8785 vectors: `testdata/{input,output,outhex}` and a deterministic 100M-line number file with published prefix
    hashes. https://github.com/cyberphone/json-canonicalization/tree/master/testdata

### How noble-curves tests

12. noble-curves 2.4.0 has per-standard test files (including `webcrypto`, `acvp`, `ed25519`, `nist`), vector
    directories (`acvp-vectors`, `wycheproof`, ...), `"test": "node --no-warnings test/index.ts"` plus Deno, Bun and slow
    variants, and minimal dev dependencies. https://github.com/paulmillr/noble-curves/tree/main/test ;
    https://github.com/paulmillr/noble-curves/blob/main/package.json
13. noble-curves publishes third-party security review reports (Trail of Bits 2023, Kudelski 2023, Cure53 2024).
    https://github.com/paulmillr/noble-curves/tree/main/audit

### Supply chain

14. tj-actions/changed-files (CVE-2025-30066, March 2025): a compromised token let attackers repoint most version tags to
    a malicious commit that dumped runner secrets into public logs; over 23,000 repositories used it.
    https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised
15. chalk/debug (8 September 2025): a maintainer was phished via a look-alike npm domain; malicious versions of 18–25
    packages carrying wallet-hijacking code were live for about 2.5 hours.
    https://endorlabs.com/learn/major-supply-chain-attack-compromises-popular-npm-packages-including-chalk-and-debug ;
    https://www.stepsecurity.io/blog/20-popular-npm-packages-compromised-chalk-debug-strip-ansi-color-convert-wrap-ansi
16. Shai-Hulud (September 2025): a self-replicating worm spread via post-install scripts through compromised maintainer
    accounts; GitHub removed 500+ packages and announced restrictions: 2FA local publishing, 7-day granular tokens or
    trusted publishing (GA since July 2025), classic tokens deprecated, TOTP replaced by FIDO 2FA.
    https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/
17. Shai-Hulud 2.0 (November 2025) moved to **preinstall** scripts, affected about 1,000 packages and exposed more than
    25,000 repositories. https://www.sysdig.com/jp/blog/return-of-the-shai-hulud-worm-affects-over-25-000-github-repositories ;
    https://www.elastic.co/blog/shai-hulud-worm-2-0-updated-response
18. `npm audit signatures` verifies registry signatures of installed packages (npm ≥ 8.15.0) and errors on missing
    signatures from a signing registry. https://docs.npmjs.com/verifying-registry-signatures

## Consequences for the spec

- §10 mutation testing: the TAP runner makes each file one test (finding 1), so split tests into many small files,
  roughly one per rule (E1, E2, V1, D1, ...). Mutate only core files.
- §10 mutation testing: set `thresholds.break` (finding 2) as a backstop (e.g. 95) under the existing rule that every
  survivor is killed or carries a reviewed `Stryker disable` reason. Do not exclude `StringLiteral` on the core:
  mutants of `muid/v1\n` and `muid-root\n` (§4, §5) must be killed by committed record-id vectors.
- D1, D2: EqualityOperator mutants on `now < exp` and `nbf − skew ≤ now` are killed by a boundary property over
  `now ∈ {nbf − skew − 1, nbf − skew, exp − 1, exp}`.
- §2, D4: a BooleanLiteral mutant of `zip215: false` must be killed by a vector.
- §10: mutation score is necessary, not sufficient (finding 3, ~17% uncoupled), which is the case for targeted
  negative controls alongside Stryker.
- §10: lower fast-check `numRuns` under Stryker and use `incremental` on pull requests; run full mutation and
  high-iteration runs on schedule.
- E2: properties: `decode(encode(v))` deep-equals `v` and `encode(decode(encode(v)))` is byte-identical over a
  domain generator; byte-level mutations of `encode(v)` (whitespace, key swap, duplicate key, `\uXXXX` escape, leading
  `+` or zero, `1.0`, `1e0`, `-0`, lone surrogate escape, BOM) either throw on decode or re-encode to themselves.
- E1: generate near pairs (one leaf changed: `"1"` vs `1`, `[]` vs `{}`, swapped keys), not only random pairs, and
  assert equal bytes ⇒ equal values (finding 6 lists the shapes that break serialisers).
- E3: generate out-of-domain values (floats, `-0`, `NaN`, `null`, `undefined`, sparse arrays, `__proto__`/`constructor`
  or uppercase or 33-character keys, lone surrogates, `Map`, `Date`, getters, null-prototype objects, `2**53`) and
  assert `encode` throws.
- §3: two spellings of one key (escape, NFC/NFD, duplicate) must be rejected; NFC and NFD forms are different keys
  and non-ASCII keys fail the key regex.
- F3: a metamorphic property: for stricter options (more `revoked`, fewer `roots`/`witnessKeys`, smaller `skew`),
  `verify(r, stricter).ok ⇒ verify(r, ctx).ok`.
- D1: a record without `nbf` always rejects.
- F1, F4: model-based tests (`fc.commands`) over issue, delegate, revoke, advance-time and verify, compared with a
  simple model.
- §10: commit shrunk counterexamples as literal unit tests; check generator statistics so a meaningful share of
  generated valid records reaches `ok: true` (otherwise "never accepts a forged record" passes vacuously).
- §10 scheduled fuzzing: a Jazzer.js harness asserting byte-exact `encode(decode(b)) === b` (E2) and a `verify`
  harness asserting no unexpected throw, no `ok: true` without a known root, and a frozen result. Jazzer.js is a native
  addon: install it only in the fuzz job, pinned exactly, outside the `--ignore-scripts` gate (finding 7).
- §10 known-answer vectors: a per-file verdict policy as committed data: Wycheproof valid → accept, invalid → reject,
  Ed25519 acceptable → **reject** (D4, finding 9); speccheck 0–11 → reject; loaders assert exact counts (210, 484) and
  non-empty accept and reject buckets (findings 8–10).
- §10, §4: expected canonical bytes and record ids are produced once by an independent tool (a separate JCS
  implementation and hash library), committed as hex, and never computed by the code under test.
- §10 differential oracles: encoder vs a reference JCS (finding 11); noble Ed25519 vs WebCrypto on valid vectors only;
  P-256 vs WebCrypto (DER converted to P1363 in the test) and SimpleWebAuthn. noble's own suite is a model (finding
  12).
- §10 negative controls, one per rule: an encoder that does not sort keys (E2); a decoder that accepts duplicate keys
  (E2); a verifier that skips the `v` check (V1); one that accepts a missing `nbf` (D1); one where a caller option
  restores trust (F3); one that re-serialises instead of verifying received bytes (§4); one with `zip215: true` (§2,
  D4); a storage adapter that returns `{ absent: true }` on error (§7). CI must see the suite fail against each.
- §10 linter gates: a fixture containing every banned construct with a CI step asserting the exact number of findings,
  so a renamed path cannot make rules vacuous; `semgrep --test` annotations; a 1,501-line fixture for the line budget
  (§9); a duplicated-block fixture for jscpd.
- F1, §10: extend the Semgrep bans to `.then(` and `Promise`; for the `{}`-seeded serializer rule, ban
  `Object.assign({}`, spread into `{}`, `for…in` and unsorted `Object.keys` in core; allow only one module to call
  `ed25519.verify`/`p256.verify` and one to call `TextDecoder`.
- not yet in spec (§10): fail CI on any skipped or TODO test, or a drop in test count against the default branch.
- §10 supply chain: SHA-pinned actions (finding 14); `npm ci --ignore-scripts`, which also blocks preinstall
  (finding 17), plus `ignore-scripts=true` in the repository `.npmrc` for local installs; exact pins and a committed
  lockfile for the two noble packages; `npm audit signatures` (finding 18).
- not yet in spec (§10): a dependency cooldown of a few days would have avoided the 2.5-hour chalk/debug window
  (finding 15); `permissions: {}` at workflow level with per-job grants; `persist-credentials: false`; CODEOWNERS on
  workflows, core, vectors and lockfile; npm trusted publishing only, no stored tokens (finding 16).
- not yet in spec: a small TLA+, Alloy or Quint model of delegation, revocation and time windows checking: no accepted
  delegate action outside `[nbf − skew, exp)`; no depth-two delegation; revocation by an unauthorised signer has no
  effect; adding a revocation or removing a pinned key never turns reject into accept. Model traces can be exported as
  vectors.

## Unverified

- Google's mutation-testing study (Petrović et al., ICSE 2021): surviving mutants shown in code review lead to more and
  better tests; Google shows few diff-scoped mutants and suppresses unproductive ones.
- Stryker disable comment syntax and the full mutator list.
  https://stryker-mutator.io/docs/mutation-testing-elements/supported-mutators/
- fast-check v4 API names (`fc.commands`, `fc.modelRun`, `fc.scheduler`, `fc.statistics`, `fc.string({unit})`, seed and
  path replay). https://fast-check.dev/docs/introduction/
- Jazzer.js v4 ESM and Node version support; OSS-Fuzz acceptance of JavaScript projects.
- Semgrep rule syntax (`paths`, `metavariable-regex`, `--test` annotations), ESLint `no-restricted-syntax` selectors,
  dependency-cruiser `forbidden` rules, eslint-plugin-boundaries. https://docs.semgrep.dev/writing-rules/rule-syntax ;
  https://eslint.org/docs/latest/rules/no-restricted-syntax ;
  https://github.com/sverweij/dependency-cruiser/blob/main/doc/rules-reference.md
- CodeQL setup for public repositories (`security-extended`, custom QL packs) and JS query ids (`js/redos`,
  `js/prototype-polluting-assignment`, ...); a custom query that every `ok: true` return is dominated by a signature
  check. https://docs.github.com/en/code-security/code-scanning/managing-your-code-scanning-configuration/codeql-query-suites
- RFC 8032 §7.1 test vectors (TEST 1, 2, 3, 1024, SHA(abc)).
- Test practice at libsodium, BoringSSL, Tink and libsignal; HACL\*/libcrux; TLA+/TLC/Apalache, Alloy 6, Quint and hax
  status in 2026. https://github.com/informalsystems/quint ; https://github.com/cryspen/hax
- OpenSSF Scorecard checks, gitleaks, GitHub private vulnerability reporting and push protection on public
  repositories, zizmor, StepSecurity harden-runner. https://github.com/ossf/scorecard ; https://github.com/zizmorcore/zizmor
- `npm audit signatures` also verifying provenance attestations; noble releases carrying provenance.
- A later "Mini Shai-Hulud" variant shipping with valid provenance (press report), which would show provenance attests
  the building workflow, not its integrity.
- Renovate `minimumReleaseAge` and Dependabot cooldown option names.
- `necessist` support for JavaScript. https://github.com/trailofbits/necessist
- Estimates: 1–3k mutants for a 1,500-line core; 1–3 days for a TLA+/Quint model of this size.
