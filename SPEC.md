# muid — threat model and record spec

Status: draft 1. Nothing here is implemented. Every invariant below gets a test before the code it governs
(see `TESTING.md`). Sources and reasoning for each rule are in [`research/`](research/README.md).

## 1. Trust boundary

**Trusted:** code running in the page that embeds the core (same origin), the JS engine, `@noble/curves`,
`@noble/hashes`.

**Untrusted:** every byte that crosses a boundary — network, `postMessage`, another origin, storage read back (treated
as possibly corrupt), provider responses, witness responses. Untrusted bytes are parsed exactly once, by one parser,
into frozen plain data. Nothing else reads them.

| Actor | Can | Cannot |
|---|---|---|
| User | hold one or more root passkeys; issue and revoke delegations | — |
| Delegate (device, app, machine key) | sign within its delegation's audience, scope and window | widen its scope; outlive its expiry; delegate further |
| App on another origin | ask the id origin for actions; receive results | read keys or stored records of the id origin; choose the audience a delegation names |
| Witness | attest that a provider account maps to a root, within the witness key's window | attest without the root's proof of possession bound to that sign-in |
| Provider (GitHub, Google, ORCID) | authenticate the account at attestation time | — (trusted for account control only) |
| Passkey sync provider (Apple, Google) | restore a synced passkey to a device after its own account recovery | — (see threats) |
| Network attacker | read, drop, replay, reorder, modify any message | forge a signature |
| Remote phisher | persuade the user to approve something | — (see threats) |

**Threats in scope beyond the table:**
- **Sync-provider account takeover.** Whoever recovers the user's Apple or Google account can obtain the synced root
  passkey. Mitigation: more than one root per user, in different sync ecosystems; delayed, contestable succession (§5).
- **Unverified local use.** Software on the device that drives the authenticator without user verification.
  Mitigation: the UV flag is required on every root assertion (W2).
- **Approval phishing.** A remote attacker induces the user to approve an attacker's key (device-code phishing).
  Mitigation: machine onboarding starts on the id origin and shows the key fingerprint (§8).

**Trusted, and therefore hardened:** the id host — its DNS, registrar, TLS certificate issuance and hosting. Whoever
serves script on the id origin can obtain assertions from every user's root, so a hijacked or lapsed domain is a
compromise of every root. Required: registrar lock, DNSSEC, CAA, long registration, a strict CSP with SRI, and a
minimal page built reproducibly. `rp_id` is permanent: every root id commits to it, so a domain move is a succession
for every user.

**What a root proves:** a WebAuthn assertion is a P-256 signature over bytes, which anyone holding a P-256 key can
produce with any flags, origin and `rp_id`. W1–W5 protect a real passkey from use through another origin; they cannot
show that a root *is* a passkey. Roots are free to create and carry no sybil weight of their own; weight comes only
from attestations and the separate reputation layer.

**Out of scope:** a compromised OS or browser; a compromised provider; the witness learning which account maps to
which root.

## 2. Primitives

- **Delegate and witness signatures:** Ed25519 via `@noble/curves`,
  `ed25519.verify(sig, msg, pub, { zip215: false })`. The option is always passed explicitly.
- **Root signatures:** WebAuthn assertions from a passkey (ES256 / P-256), verified with
  `p256.verify(sig, authData ‖ SHA-256(clientDataJSON), pub, { format: 'der', lowS: false, prehash: true })`.
  `lowS: false` is required: passkeys emit high-S signatures. A root signature is therefore malleable, so
  **no identifier, set key or cache key is ever derived from a signature.**
- **K1 KEY SHAPE:** an Ed25519 public key is accepted only if it decodes canonically, is not small-order and is
  torsion-free (`isTorsionFree()`); strict mode alone admits mixed-order keys. A P-256 key is stored only as the
  65-byte uncompressed point, decoded once from COSE when the root is created.
- **K2 NO THROW ESCAPES:** any library call that throws inside a decision is a reject.
- **Hash:** SHA-256 (`@noble/hashes`).
- **Bytes in text:** lowercase hex. Exception: WebAuthn fields keep their standard unpadded base64url. Each decoder
  rejects any input that does not re-encode to itself.
- **Time:** integer seconds since the Unix epoch. `now` is always a parameter, never read from a clock inside the core.
- **Delegate key custody (not core):** in browsers a delegate key is a non-extractable WebCrypto Ed25519 key, so the
  secret never sits in JS memory; verification always uses noble, for one verdict everywhere. Ed25519 signing is
  deterministic, so both must produce identical signature bytes for the same key and message.
- **Pinning:** library versions are pinned exactly; an upgrade is a reviewed change that re-runs every vector suite.

Research: [`signatures.md`](research/signatures.md), [`webauthn.md`](research/webauthn.md).

## 3. Encoding

Records are RFC 8785 (JCS) text over a restricted value domain:

- objects whose keys match `^[a-z][a-z0-9_]{0,31}$`;
- strings that are well-formed Unicode (no normalisation is applied or required);
- safe integers (`|n| ≤ 2^53−1`); no floats, no `-0`;
- `true`, `false`; dense arrays. No `null` — an optional field is absent.

**E1 INJECTIVE:** distinct values encode to distinct bytes.
**E2 CANONICAL INPUT:** `decode(b)` succeeds only if `encode(decode(b))` equals `b` byte for byte. This rejects
duplicate keys, whitespace, alternative escapes and key-order variants.
**E3 TOTAL OR REFUSED:** a value outside the domain throws; nothing is silently dropped or converted.
**E4 BOUNDED:** input longer than `MAX_BYTES` is refused before it is parsed; nesting deeper than `MAX_DEPTH` is
refused before recursion can exhaust the stack.

Research: [`encoding.md`](research/encoding.md).

## 4. Envelope

```
{"payload":"<JCS text of {v, type, body}>","sig":<signature object>}
```

- The envelope is itself canonical (E2).
- **Signed bytes** = `UTF-8("muid/v1\n") ‖ UTF-8(payload)`. The verifier checks the signature over the payload bytes
  it received, then decodes those same bytes. It never re-serialises in order to verify.
- **Record id** = hex SHA-256 of the signed bytes. It excludes the signature (§2).
- **V1 VERSION:** `v` must equal 1. Any other value is rejected.
- **V2 TYPE:** the verifier is told which `type` it expects; a mismatch is rejected.
- **V3 ONE ALGORITHM PER TYPE:** the record type fixes the signature algorithm and the signer's role. Nothing in the
  record selects either.

## 5. Record types

**root** — signed by its own passkey (proof of possession). Registration with `attestation: "none"` signs nothing
the verifier can use, so the root record is signed by a separate assertion made immediately after `create()`.
`{ pub, rp_id, cred_id, created }`. Root id = hex SHA-256(`"muid-root\n"` ‖ `rp_id` ‖ `"\n"` ‖ point bytes).

**delegation** — signed by a root (passkey assertion). Never by an Ed25519 key.
`{ root, subject, aud, scopes, nbf, exp }`. `subject` is an Ed25519 public key; `aud` is one exact origin;
`scopes` is a non-empty sorted list of distinct scope strings (`^[a-z][a-z0-9_.:-]{0,63}$`). A scope's meaning
belongs to the relying party; the core checks only exact membership — no prefix, wildcard or hierarchy rule.
- **D1 WINDOW:** `nbf − skew ≤ now < exp`. Skew applies to `nbf` only; it never extends `exp`.
- **D2 LIFETIME:** `exp − nbf ≤ MAX_DELEGATION`.
- **D3 DEPTH ONE BY TYPE:** only a root can sign a delegation (V3). There is no depth counter to get wrong.
- **D4 SUBJECT KEY:** the subject key satisfies K1 at issue and at verify.
- **D6 SUBJECT CONSENT:** a delegation is valid only together with an Ed25519 signature by `subject` over the
  delegation's record id (domain `"muid/v1/accept\n"`). Without it, a root could attach someone else's public key to
  its identity and have that key's signatures counted as its own.
- **D5 AUDIENCE:** `aud` is compared to the relying origin by exact string equality, after the origin itself is
  checked to be in canonical form (`https`, lowercase ASCII host with IDNs in punycode, no trailing slash, no default
  port, no path, query, fragment or userinfo).

**attestation** — signed by a witness key.
`{ root, provider, account, nbf, exp }`.
- **A1 WITNESS KEY:** the key is in the pinned set and inside its own window at `now`.
- **A2 POSSESSION:** the sign-in that produced it carried a root (or `attest`-scoped delegate) signature over that
  session's OAuth `state`; for OIDC providers the hash of that signature is also the `nonce`, so the provider's id
  token commits to it.
- **A3 SUBJECT:** identity is the pair (`provider`, `account`). `provider` is one of a closed list, each mapped to one
  pinned issuer. `account` is the provider's stable id in its canonical form: GitHub numeric user id (decimal, no
  leading zeros); Google `sub`; ORCID iD (`dddd-dddd-dddd-dddX`, ISO 7064 MOD 11-2 check digit). Never an email,
  handle, login or domain.

**link** — signed by a root. `{ root, peer, nbf }`. Two roots are one identity when each has linked the other.

**retire** — signed by a root mutually linked to `target`. `{ target, by, effective }`.
- **R1 DELAY:** `effective` is at least `RECOVERY_DELAY` after the retire record's anchored time (open decision 2).
- **R2 VETO:** a `veto` record `{ retire }` signed by `target` before `effective` cancels it.
- **R3 EFFECT:** from `effective`, delegations by `target` fail and `target` can sign nothing further.

**revocation** — signed by the root, or by the witness for its own attestations, or by a delegate for itself.
`{ target, at }`. `target` is a record id. A revocation may be pruned once its target's `exp` has passed.

Reputation is computed from records. It is never signed as a record.

Research: [`delegation.md`](research/delegation.md), [`oidc-witness.md`](research/oidc-witness.md),
[`passkeys-and-recovery.md`](research/passkeys-and-recovery.md).

## 6. The decision function

```
const v = verifier({ rpId, origin, witnessKeys, skew })      // trust anchors: fixed configuration, frozen
v.verify(envelopeText, { expectType, now, roots, revoked })  // per call: what is being checked, and when
  -> frozen result | { ok: false, reason }
```

Trust anchors (`rpId`, `origin`, `witnessKeys`, `skew`) are set once, when the verifier is constructed, and cannot be
changed per call. Per-call inputs can only narrow what is accepted: `roots` lists the roots the caller already holds
verified records for, and `revoked` adds revocations.

- **F1 SYNCHRONOUS AND PURE:** no `await`, no clock, no storage, no network inside a decision.
- **F2 DENY BY DEFAULT:** every branch that is not an explicit accept is a reject. An unknown field is a reject.
- **F3 OPTIONS ONLY REMOVE TRUST:** no per-call input can make a record pass that the same verifier would reject with
  narrower inputs (fewer roots, more revocations). Tested as a monotonicity property.
- **F4 EXPIRY FIRST:** short-lived records do the revocation work; the revoked set is a backstop.

**Root assertion checks** (the `sig` object of a root-signed record: `{ covers, cred_id, authenticator_data,
client_data_json, signature }`; WebAuthn fields base64url):
- **W0 COVERAGE:** one assertion may cover several records, so a first run needs one prompt for the root record and
  the first delegation together. `covers` is a sorted list of 1–8 distinct record ids (lowercase hex) that contains
  this record's own id. A single record is a list of length one; there is no other form.
- **W1 CLIENT DATA:** `type` is `"webauthn.get"`; `challenge` equals
  base64url(SHA-256(`UTF-8("muid/v1/assert\n")` ‖ the ids in `covers`, each followed by `"\n"`)) exactly — a domain
  distinct from the signed-bytes prefix `"muid/v1\n"`; `origin` equals the configured id origin exactly;
  `crossOrigin` is absent or `false`; `topOrigin` is absent.
- **W2 AUTHENTICATOR DATA:** `rpIdHash` equals SHA-256(`rp_id`); UP and UV are set; AT and ED are clear and no bytes
  follow the 37-byte header; BS set implies BE set.
- **W3 SIGNATURE:** strict DER, verified as in §2.
- **W4 CREDENTIAL:** `cred_id` equals the root record's `cred_id`.
- **W5 NO COUNTER:** the signature counter is not consulted (synced passkeys report a constant).

Research: [`webauthn.md`](research/webauthn.md).

## 7. Storage interface (later step)

`get(key)` returns `{ value }` or `{ absent: true }`, or throws. A failed read is never reported as absence. A guard
test fails the build on any direct `indexedDB` or `localStorage` use outside the one adapter.

## 8. The id origin and machine onboarding (not core)

- The id origin is a dedicated host serving nothing else, with no subdomains. `rp_id` and the exact origin are
  deployment configuration, compared exactly; no suffix or wildcard rule exists anywhere.
- Root registration and every root-signed action happen in a top-level id-origin window (popup or redirect).
  Cross-origin iframe `create()` is not available in Safari or iOS browsers.
- **I1 SENDER:** a request is accepted only if `event.source` is this window's opener (or parent, for an iframe) and
  `event.origin` is a canonical origin (D5). `document.referrer` is never consulted.
- **I2 REPLY:** a reply is posted with `targetOrigin` equal to the request's `event.origin` — never `'*'` — and is not
  sent if the opener has navigated away.
- **I3 AUDIENCE FROM THE CHANNEL:** `aud` is the request's `event.origin`. A requester cannot name a different
  audience.
- **I4 WHAT YOU SEE IS WHAT YOU SIGN:** the page renders `aud`, `scopes` and `exp` of every record in `covers`, from
  the exact payloads whose ids become the challenge; nothing is computed between display and signing.
- **I5 NO CACHED VERIFICATION:** every root assertion is a fresh ceremony with user verification; nothing is cached
  across actions.
- **U1 FIRST RUN:** one id-origin window and at most two user-verification prompts — passkey creation, then one
  assertion covering the root record and the app's first delegation (W0).
- **U2 STEADY STATE:** at most one user-verification prompt per device per 30 days in ordinary use. Delegation
  lifetimes are chosen to meet U2 (open decision 3), and renewal happens during a root ceremony the user is already
  in where possible. A delegation cannot be renewed without a root assertion; "silent renewal" does not exist.
- **U3 ONE ROOT IS ENOUGH TO START:** a first-time user has one root. Adding a second and third is encouraged later
  and never required to proceed.
- Machine onboarding: the machine generates its key first; the user opens the id origin and confirms the key
  fingerprint shown there matches the machine's. If a device code is used, it is one-time, short-lived and
  rate-limited, and the result is a delegation, never a bearer token. The `attest` scope is never granted this way.
- The witness hard-codes its issuers and their signing-key endpoints, follows no discovery redirect, and uses a
  distinct redirect URI per provider (GitHub returns no `iss`).

## 9. Open decisions

1. **Claims and time — the most important open decision.** The spec does not yet define the record a delegate
   signs. Any timestamp inside a record is chosen by its signer, so a delegate whose delegation has expired could
   backdate a claim into the old window, and a compromised root could backdate a `retire`. Either (a) claims are
   **ephemeral**: verified on receipt against the verifier's `now`, and unverifiable once the delegation lapses; or
   (b) claims are **durable**: a time anchor (a witness countersignature over the record id and the time it was seen)
   fixes when the record existed, and authority is judged at that anchored time. The same anchor would serve R1.
   Either way, a claim names the record id of the delegation it is made under, so a signature made under one
   delegation is never accepted under another. Revocation semantics follow from this choice: whether a revocation
   is retroactive, what `at` means, and whether a verifier may ever forget a revocation it has seen.
2. **Recovery under symmetric compromise.** Two mutually linked roots cannot tell the owner from a thief: each can
   retire the other and each can veto. Options: (a) a 2-of-3 root quorum retires without veto; (b) a priority order
   fixed at link time (safe only if the thief does not hold the higher root); (c) a vetoed retire freezes every root
   of the identity, which is then re-established from provider attestations. R1–R3 change with the choice.
3. **Lifetimes, per kind of subject** (own device, third-party app, machine), chosen to meet U2; attestation
   lifetime; `skew`; `RECOVERY_DELAY` (if recovery keeps a delay).
4. **Machine autonomy:** which scopes a machine may hold without per-action approval, and for how long.
5. **Boundary parser:** a schema library (valibot) or a hand-written strict parser for this small fixed set of types.
6. **`clientDataJSON` parsing:** the WebAuthn spec's limited (prefix) verification, which needs no JSON parser, or a
   strict JSON parse confined to the WebAuthn module. Decided by testing real browser output.

## 10. Budget

Trusted core ≤ 1,500 lines. Going over is a design problem, not a reason to raise the budget.

## 11. Automated assurance

A tool counts only once it runs in CI and can fail the build. Each item lands with the first code it applies to,
never afterwards. Details and thresholds: `TESTING.md`; sources: [`assurance.md`](research/assurance.md).

**Gates on every pull request**

| Gate | What it fails on |
|---|---|
| Unit + property tests (`node --test`, fast-check) | any invariant in this spec broken over adversarial generated inputs |
| Known-answer vectors, committed as data | RFC 8785; RFC 8032, Wycheproof Ed25519 and the Taming-EdDSA cases; Wycheproof ECDSA P-256 DER — with the loaded count asserted |
| Differential oracles | encoder ≠ reference JCS; an assertion we accept that SimpleWebAuthn rejects (one-directional; known differences are a committed list) |
| Negative controls | a deliberately broken implementation, one per known bug class, that the suite fails to reject |
| Mutation testing (Stryker, tap runner) on the core | score below the break threshold, or a surviving mutant not explained in the PR |
| Branch coverage on the core | any uncovered branch |
| Custom rules (Semgrep, each with its own `--test` fixtures) | in core files: `async`/`await`, `Date.now`, `Math.random`, `JSON.parse` outside the parser, `indexedDB`/`localStorage` outside the adapter, a `{}`-seeded serializer, imports other than noble and the core itself |
| Duplication (jscpd, threshold 0 on the core) | a copied trust-path block |
| Line budget | core over 1,500 lines |
| Skipped tests | any skipped or `todo` test |
| CodeQL (`security-extended`) | new alerts |
| Secret scanning (gitleaks, plus GitHub push protection) | any credential-shaped string |
| Supply chain | lockfile drift; non-exact pins; install scripts (`npm ci --ignore-scripts`); unverified registry signatures; a dependency version younger than the cooldown |
| CI hardening | an action not pinned by commit SHA; a workflow with write permissions it does not need; any `pull_request_target` |

**Scheduled, not gating**

- Long fuzz runs of `decode` and `verify` (fast-check at high iteration counts; Jazzer.js).
- A model of the delegation, revocation, succession and time-window rules (Quint or TLA+), with its traces replayed
  against `verify`.
- An adversarial review agent against the core. Its findings go to a **private** security advisory, never a public
  issue.
- After every fix, a variant-analysis sweep for siblings of the bug.
