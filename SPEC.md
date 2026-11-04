# muid — threat model and record spec

Status: draft 2. Everything below is implemented in `src/` except the revocation record's own check (§5), which the
witness performs. Every invariant below
gets a test before the code it governs (see `TESTING.md`). Sources and reasoning for each rule are in
[`research/`](research/README.md).

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
| Witness | attest that a provider account maps to a root, within the witness key's window; anchor and settle membership records (R3, R4) | attest without the root's proof of possession bound to that sign-in; change membership without the roots' signatures |
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
produce with any flags, origin and `rp_id`. W0–W3 protect a real passkey from use through another origin; they cannot
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
- **K4 STRICT SIGNATURE POINT:** an Ed25519 signature's R must decode canonically, not be small-order, and be
  torsion-free. Without this a signer can add a small-order component to R that noble accepts and WebCrypto
  rejects — two verdicts on one record. Strict rejection makes every engine agree.
- **K2 NO THROW ESCAPES:** any library call that throws inside a decision is a reject. Byte inputs (`message`, a DER
  `sig`) are copied from their internal slots on entry, so a `Uint8Array` subclass cannot change what is checked while
  it is being checked; a detached one is a programming error (`message`) or an encoding refusal (`sig`).
- **K6 P-256 CHECKS, IN ORDER:** `checkP256(sig, message, key)` returns `{ ok: true }` or `{ ok: false, reason }` and
  never throws for any `sig` and `key` value (a `message` that is not a `Uint8Array` is a programming error). `key` is
  130 lowercase hex characters: the uncompressed point `04 ‖ x ‖ y`. `sig` is the DER bytes. Reasons: `key-encoding`
  (not that hex, or not `04`-prefixed), `key-point` (not on the curve, or the point at infinity), `sig-encoding` (not
  strict DER, or r or s outside [1, n−1]), `sig-invalid` (verified with `lowS: false`, `prehash: true`).
- **K5 ED25519 CHECKS, IN ORDER:** `checkEd25519(sig, message, key)` returns `{ ok: true }` or `{ ok: false, reason }`
  and never throws for any `sig` and `key` value (a `message` that is not a `Uint8Array` is a programming error).
  `key` is 64 lowercase hex characters, `sig` 128. The first failure is the reason: `key-encoding` (not that hex),
  `key-point` (not a canonical encoding of a curve point), `key-small-order`, `key-mixed-order` (K1);
  `sig-encoding`; `sig-r-point`, `sig-r-small-order`, `sig-r-mixed-order` (K4); `sig-s-range` (S ≥ L); `sig-invalid`
  (the equation fails, checked by `ed25519.verify` with `zip215: false`). Built-ins the module uses are captured at load
  (E7); those the library uses when called can only make it fail closed if patched — a reject, never a throw or a
  new accept — which is tested, not proved.
- **Hash:** SHA-256 (`@noble/hashes`).
- **Bytes in text:** lowercase hex. Exception: WebAuthn fields keep their standard unpadded base64url. Each decoder
  rejects any input that does not re-encode to itself.
- **Ids inside hashes and signatures:** wherever an id (record, root or identity id) is an input to a hash or a
  signature outside a record payload, it is its 32 raw bytes, never its hex text — except in the W1 challenge, which is
  defined as text. Inside a payload, ids are hex text, and the payload's bytes are what is hashed and signed.
- **Time:** integer seconds since the Unix epoch. `now` is always a parameter, never read from a clock inside the core.
- **K3 NON-EXTRACTABLE DELEGATE KEYS:** in browsers a delegate key is generated as a WebCrypto Ed25519 key with
  `extractable: false`, so the secret never sits in JS memory and cannot be exported by any script, ours included. A
  machine's key lives in a file readable only by its owner (mode `0600`). Verification always uses noble, for one
  verdict everywhere. Where WebCrypto signs Ed25519 deterministically (Chromium, Firefox, Node), WebCrypto and noble
  must produce identical signature bytes for the same key and message — a differential test. Safari signs through
  CryptoKit, which randomises Ed25519 signatures, so there the test is that noble verifies what WebCrypto signs.
  (Custody code is not core, but this rule binds it.)
- **K7 ED25519 MESSAGES:** an Ed25519 key signs only `UTF-8("muid/v1\n") ‖ payload` (a record: the payload's
  `type` separates kinds; a claim is a record of its own type) or `UTF-8("muid/v1/<tag>\n") ‖` a
  fixed-length suffix, with tags from a closed list: `accept` (D6, 32 bytes). Custody code never signs bytes it did
  not build. These prefixes differ by their eighth byte and none is a prefix of another.
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
**E4 BOUNDED:** `MAX_BYTES` = 65,536 bytes of UTF-8 and `MAX_DEPTH` = 16 (the top-level object is depth 1). Input
longer than `MAX_BYTES` is refused before it is parsed. Encoding stops as soon as its output would exceed
`MAX_BYTES`, so work is bounded by the limit even when one object is reachable by many paths. Nesting deeper than
`MAX_DEPTH` is refused before recursion can exhaust the stack. Nothing is enumerated or copied past what the limit
allows. Every value is followed by at least one byte, so: an array of length L is refused on entry when the bytes
already written + 2L + 2 exceed the limit; a string, before it is scanned, when the bytes already written + its
length + 3 do, and before it is copied, when they + its exact escaped size + 3 do (a control character escapes to six
bytes); an object with k keys, when 6k + 1 does. Each bound is a true minimum, so none refuses anything that fits; the
array and string bounds are attained exactly, and tests pin a value that fits to the last byte.
**E5 ONE REASON:** a refusal carries exactly one reason code, and it is the same for every implementation. The top
level must be a plain object. Each container is checked on entry — cycle, then depth, then plainness (prototype, internal slots, and no
`Symbol.toStringTag` the slot check could read: none of its own, nor one on `Object.prototype` for an object that
inherits from it), then width (E4), then shape (symbol keys, array holes and extra properties). An object's members are
then visited in canonical key order, each key checked (grammar, then data-property descriptor) before its value;
array elements in index order. The first violation found is the reason. Numbers are checked in the order non-finite,
`-0`, non-integer, unsafe integer. Reason codes: `top-level`, `key`, `symbol-key`, `accessor`, `non-enumerable`,
`non-plain`, `array-shape`, `cycle`, `depth`, `size`, `null`, `undefined`, `non-finite`, `negative-zero`, `float`,
`unsafe-integer`, `type`, `surrogate`, `syntax`, `non-canonical`, `exotic`. `exotic` covers an array length that is not
a non-negative safe integer, anything an object throws
of its own while being read (a Proxy trap, a revoked Proxy) and a key listed without a descriptor; nothing other
than an `EncodingError` ever leaves `encode` or `decode`.
**E6 READ ONCE:** every prototype, key list, array length and property descriptor is read exactly once per encode, and
the value encoded is the value read. A Proxy cannot be detected in a browser; with E4 and E6 it cannot loop, read
twice or escape with a foreign error, and it can choose only what is encoded, as any caller can by building the
object. The bytes are what get signed.
**E7 OWN INTRINSICS:** the encoder uses only built-ins captured when its module loaded, called through a captured
`Reflect.apply`, and no iteration protocol; code that patches a built-in afterwards changes no result, except that
a `Symbol.toStringTag` defined on `Object.prototype` (never read) leaves no object inheriting from it plain: each is
refused, failing closed.
**E8 NULL PROTOTYPES:** `decode` returns objects and arrays with null prototypes, deeply frozen, so prototype pollution
elsewhere in the page cannot make an absent field read as present. Arrays with a null prototype are in the domain.

**Residual (accepted):** an object with internal slots that only an exception-throwing brand check could detect —
Symbol and BigInt wrappers, Map, Set, WeakMap, WeakSet, WeakRef, ArrayBuffer, SharedArrayBuffer, Promise — encodes as
its own properties if code in the page has given it a plain prototype. Checking for them would slow every plain object
about a thousandfold; producing one requires deliberate re-prototyping by trusted code, and neither `decode` nor a
Proxy can produce one. Number, String and Boolean wrappers, Date, RegExp, Error, arguments objects, typed arrays and
DataView are detected.

Research: [`encoding.md`](research/encoding.md).

## 4. Envelope

```
{"payload":"<JCS text of {v, type, body}>","sig":<signature object>}
```

- The envelope is itself canonical (E2). Its keys are exactly `payload` and `sig`, except for a `root`, whose envelope
  is `{"payload": …}` alone (§5: a root is unsigned).
- **Signed bytes** = `UTF-8("muid/v1\n") ‖ UTF-8(payload)`. The verifier decodes the payload text it received and
  checks the signature over those same bytes. It never re-serialises in order to verify.
- **Record id** = hex SHA-256 of the signed bytes. It excludes the signature (§2).
- **V1 VERSION:** `v` must equal 1. Any other value is rejected.
- **V2 TYPE:** the verifier is told which `type` it expects; a mismatch is rejected. Types form a closed list:
  `root`, `delegation`, `attestation`, `membership`, `freeze`, `contest`, `anchor`, `settlement`, `head`, `claim`,
  `revocation`, `receipt`. Asking
  for any other type is a programming error, not a reject.
- **V3 ONE ALGORITHM PER TYPE:** the record type fixes the signature algorithm and the signer's role. Nothing in the
  record selects either.
- **V4 SHAPE BEFORE MEANING:** `open(text, type)` checks, in this order, and refuses with the first that fails:
  `envelope-encoding` (the text is not a canonical encoding), `envelope-shape` (keys other than above, `payload` not a
  string, `sig` not an object), `payload-size` (V5), `payload-encoding`, `payload-shape` (keys other than `v`,
  `type`, `body`, or `body` not an object), `version`, `type`. It returns `{ id, type, body, sig, payload }` (no `sig`
  for a root), frozen,
  where `payload` is the received text itself. The signature's contents are checked by the record type's own rules,
  not here.
- **V5 PAYLOAD SIZE:** a payload, measured as the UTF-8 bytes it occupies inside the envelope (with its escapes), is
  at most `MAX_PAYLOAD` = 49,152, leaving 16 KiB of `MAX_BYTES` for `sig` and framing. `seal` refuses a larger one
  with the same reason, so nothing can be signed that could not be wrapped and opened.
- **Residual (accepted):** the record id is computed by `@noble/hashes`, which uses typed-array built-ins when called.
  Code in the page that patches those after load can change an id or make `open` throw; such code is trusted (§1)
  and could equally change the caller. The envelope's own built-ins, and its hex encoding, are captured at load.

## 5. Record types

**root** — unsigned and self-certifying. `{ pub, rp_id }`, where `pub` is the passkey public key from `create()`
(65-byte uncompressed point, 130 lowercase hex). Root id = hex SHA-256(`UTF-8("muid-root\n")` ‖ `UTF-8(rp_id)` ‖
`"\n"` ‖ the 65 point bytes). `checkRoot(text, { rpId })` opens the envelope as a `root` and returns
`{ ok: true, id, key }` or `{ ok: false, reason }`, never throwing for any `text`: V4's reasons; `root-shape` (keys
other than `pub` and `rp_id`, `rp_id` not a string, or `pub` not 130 lowercase hex starting `04`); `rp-id` (not the
configured one); `key-point` (`pub` not on the curve). Anyone can
publish anyone's root record and gains nothing: the id is derived from the key, and only the key's holder can sign
under it. The record carries nothing else: a credential id is a client-side lookup hint, not covered by any assertion
signature, and a creation time would be chosen by the signer and prove nothing.

**identity** — the identity id is hex SHA-256(`UTF-8("muid-identity\n")` ‖ the first root id as 32 raw bytes)
(`identityOf(rootId)`). It never changes, whatever
happens to its roots afterwards.

**delegation** — signed by a root (passkey assertion). Never by an Ed25519 key.
`{ identity, membership, root, subject, aud, scopes, nbf, exp }`. `root` is a member of `membership` (R6 below);
`subject` is an Ed25519 public key; `aud` is one exact origin;
`scopes` is a sorted list of 1–16 distinct scope strings (`^[a-z][a-z0-9_.:-]{0,63}$`). A scope's meaning belongs
to the relying party; the core checks only exact membership — no prefix, wildcard or hierarchy rule. `identity`,
`membership` and `root` are ids (64 lowercase hex), `subject` is 64 lowercase hex, `nbf` and `exp` are
non-negative integers.
Its envelope's `sig` is `{ root, subject }`: `root` the passkey assertion (W0–W6), `subject` the D6 signature
(128 lowercase hex).
- **D1 WINDOW:** `nbf − skew ≤ now < exp`. Skew applies to `nbf` only; it never extends `exp`.
- **D2 LIFETIME:** `exp − nbf ≤ maxLifetime` (configuration; decision 3).
- **D3 DEPTH ONE BY TYPE:** only a root can sign a delegation (V3). There is no depth counter to get wrong.
- **D4 SUBJECT KEY:** the subject key satisfies K1 at issue and at verify.
- **D6 SUBJECT CONSENT:** a delegation is valid only together with an Ed25519 signature by `subject` over
  `UTF-8("muid/v1/accept\n") ‖` the delegation's record id as 32 raw bytes. Without it, a root could attach someone
  else's public key to its identity and have that key's signatures counted as its own.
- **D7 CHECKS, IN ORDER:** `checkDelegation(text, { rootKey, rpId, origin, now, skew, maxLifetime })` opens the
  envelope itself — so the id it checks is always the id of the bytes it was given — and returns
  `{ ok: true, id, body }` or `{ ok: false, reason }`, never throwing for any `text`. The context is read once.
  Reasons: V4's, for the envelope; `delegation-shape` (body keys other than the eight, or a field of the wrong form,
  or `sig` not `{ root, subject }` with `subject` 128 lowercase hex); `scopes`; `aud` (O1); `subject-key` (K1, via K5's
  key checks); `lifetime`
  (`exp ≤ nbf` or D2); `not-yet` and `expired` (D1); `root` (the root id of `rootKey` under `rpId` is not the body's
  `root`, so a caller cannot verify one root's assertion as another's); then W6's reasons for `sig.root` with this
  record's id; then
  `subject-consent` (any K5 signature reason for `sig.subject`). Whether `root` has authority under `membership`
  (R6), and whether the verifier's view is fresh (R9), are the verifier's to decide (§6), not this check's. `skew`
  and `maxLifetime` are configuration (decision 3).
- **D5 AUDIENCE:** `aud` is the origin of the relying party — the service that verifies the delegate's signatures. It
  is compared by exact string equality, after the origin itself is checked to be canonical (O1). For an app, the
  relying party is the app (I3). For a machine, it is the service the machine calls, chosen by the user on the id
  page (§8). There is no audience form other than an origin.
- **O1 CANONICAL ORIGIN:** `isCanonicalOrigin(x)` holds exactly for strings `https://<host>` or
  `https://<host>:<port>` where `<host>` is 2–127 dot-separated labels, each 1–63 characters of `[a-z0-9-]` not
  starting or ending with `-` and without `--` in positions 3–4 (so no IDN `xn--` label), the last label not a
  number as the URL Standard's "ends in a number" check defines it — all digits, or `0x` followed by hex digits,
  possibly none — so no IPv4 address in any notation, at most 253 characters; and `<port>` is 1–65535 in decimal without leading zeros, and
  not 443. No trailing dot, slash, path, query, fragment or userinfo. Internationalised names are refused in this
  version: validating them needs IDNA rules on which URL parsers in different browsers disagree.

**attestation** — signed by a witness key.
`{ identity, root, provider, account, nbf, exp }`: the account belongs to this root within this identity.
- **A1 WITNESS KEY:** the key is in the pinned set, and its window holds both `now` and the record's whole window
  `[nbf, exp]` — so a key cannot vouch for a time before it existed or after it is retired. Deployments pin the
  attestation witness's keys separately from the membership witness's (§5 R3), so the key facing OAuth providers
  cannot sign membership.
- **A2 POSSESSION:** the sign-in that produced it carried a root (or `attest`-scoped delegate) signature over that
  session's OAuth `state`; for OIDC providers the hash of that signature is also the `nonce`, so the provider's id
  token commits to it.
- **A3 SUBJECT:** identity is the pair (`provider`, `account`). `provider` is one of a closed list, each mapped to one
  pinned issuer. `account` is the provider's stable id in its canonical form: GitHub numeric user id (decimal, no
  leading zeros, at most 20 digits); Google `sub` (1–255 printable ASCII characters, no space, as Google documents
  it); ORCID iD (`dddd-dddd-dddd-dddX`, ISO 7064 MOD 11-2 check digit). Never an email, handle, login or domain.
- **A4 CHECKS, IN ORDER:** the envelope's `sig` is `{ signature, witness }`: `witness` names the pinned key (64
  lowercase hex) and `signature` is its Ed25519 signature over the record's signed bytes (128 lowercase hex); keys
  are named, never found by trying. `checkAttestation(text, { witnessKeys, now, skew, maxLifetime })`, where
  `witnessKeys` is the pinned list of `{ key, nbf, exp }`, opens the envelope itself and returns
  `{ ok: true, id, body, witness }` or `{ ok: false, reason }`, never throwing for any `text`: V4's reasons;
  `attestation-shape` (body keys other than the six, `identity` not an id, `root` not an id, `nbf`/`exp` not
  non-negative integers,
  `provider`/`account` not strings, or `sig` not as above); `provider` (not `github`, `google` or `orcid`);
  `account` (not that provider's form); `lifetime` (`exp ≤ nbf`, or longer than `maxLifetime`); `not-yet`,
  `expired` (D1's window); `witness` (not a pinned key, or its window does not hold `now` and `[nbf, exp]` — A1); then
  K5's signature
  reasons.

**membership** — the identity's root set at one epoch. `{ identity, prev, epoch, roots }`. `roots` is a sorted list
of 1–5 distinct root ids. Epoch 1 is implicit: it is the single first root, and needs no record. `prev` is the record
id of the previous epoch's membership record — for epoch 2, the identity id — and `epoch` is one more than `prev`'s.
One membership record is carried by several envelopes with the same payload, each signed by one root. Below, "a
membership" means a membership record id, or the identity id for epoch 1.

Records the witness signs about membership (V3: witness key; checked against that key's window at their own `at`):
**anchor** `{ identity, record, at }` and **settlement** `{ identity, prev, outcome, at }`, each with A4's
`sig = { signature, witness }`. A root-signed **contest** `{ identity, record }` and **freeze**
`{ identity, membership }` complete the set. A membership, contest or freeze record may be signed by several roots,
one envelope each, so its `sig` names the signer: `{ root, assertion }`, where `assertion` is W0–W6's object.

- **R1 CHANGE BY MAJORITY:** a membership record is valid only if signed by a strict majority of `prev`'s roots
  (⌊n/2⌋ + 1 of n) and by every root it adds. A root is retired by leaving it out.
- **R2 FREEZE BY ANY:** a freeze signed by any one root of the membership it names freezes it: delegations under it
  fail, and so do delegations under a pending successor of it. A freeze of the pending record itself, by any of its
  roots (new ones included), freezes the identity; once that record settles, the freeze holds on it as the settled
  membership. Only a settled successor (R4) moves past a freeze of the settled membership. Freezing only removes trust, so any single root may do it.
- **R3 ONE ANCHOR PER EPOCH:** the witness applies R1 exactly as verifiers do (an `epoch` one more than `prev`'s
  included) and anchors a valid membership record only if its `prev` is the last settled
  membership and nothing else with that `prev` is anchored. It anchors each record once and notifies the owner. Every
  other record with that `prev` — an ordinary rival, or one arriving after settlement — is refused, never anchored.
- **R4 SETTLEMENT:** `CONTEST_WINDOW` after an anchor, the witness settles `prev`: `outcome` is the anchored record's
  id, or `contested` (R5). A settlement is final. A verifier follows settlements from the identity; after the last
  one there is at most one *pending* record — anchored, not yet settled.
- **R5 CONTEST:** a contest names the pending record it contests and is signed by a strict majority of that record's
  `prev`. The witness anchors it only while that record is pending, and refuses it otherwise; an anchored contest
  settles `prev` as `contested`, and the identity ends. Only this explicit record ends an identity; two ordinary
  records never do, so a second device or a leftover set of signatures cannot end it by accident.
- **R6 CURRENT AUTHORITY:** a delegation names the membership it is issued under. It is accepted only if that
  membership is the last settled one, or its pending successor; it is not frozen (R2); and its root is in it. While a
  successor is pending, only roots in both the last settled membership and the pending one have authority, under
  either name, so outstanding delegations from a root that stays keep working. New roots gain authority only at
  settlement, and a root being removed loses it at anchoring.
- **R7 ORDER-FREE, NEVER FORKED:** the state is a function of the *set* of membership records, anchors, settlements,
  contests and freezes the verifier holds, never of their order. The only time used is the witness's `at`. Because
  only one record per `prev` is ever anchored, a verifier holding fewer records can be behind, never on another
  branch.
- **Prior art** ([`prior-art.md`](research/prior-art.md)). R1–R6 combine three established mechanisms: rotation
  signed by thresholds of the old and the new keys (TUF root rotation, KERI); one successor per predecessor through a
  sequencer whose clock is the only time (did:plc's `prev` with serialised writes); and a queued change that is
  finalized after a delay unless cancelled (Zodiac Delay, Candide's recovery module, Argent's recovery period), with
  any one key able to lock (Argent). Four deviations are kept. Every added root signs, rather than a threshold of the
  new set, so that each new key proves possession (as D6, and Fulcio). A freeze never expires, since a thief can wait
  out an expiring lock. A contest ends the identity instead of reverting the change: established cancels assume the
  canceller is not the thief, and here a thief may hold every root the owner holds, so a reverting cancel would allow
  an endless propose-and-cancel loop. Keys are not ranked (as did:plc's are), since any one root may be stolen (§1)
  and a top-ranked key would be a single point of failure.

- **R8 STATE, AS A FUNCTION:** `membershipState(records, ctx)`, with `records` grouped by type (`roots`,
  `memberships`, `contests`, `freezes`, `anchors`, `settlements`, each a list of envelope texts) and
  `ctx = { identity, rpId, origin, witnessKeys }`, verifies each record on its own — a record that does not verify
  carries no authority and is ignored — and returns `{ ok: true, dead: true }`, or
  `{ ok: true, dead: false, identity, membership, settled, epoch, roots, pending, authority, frozen }` (`settled`
  is the last settled membership, `membership` the effective one), or `{ ok: false, reason }`
  with `unknown-identity` when no root record given is the identity's first root, or `records` when a list is
  longer than `MAX_RECORDS` (256) or cannot be read; a list that is not an array is empty. A signer already counted
  for a record is not verified again, and `MAX_RECORDS` bounds each list, so the work a caller can cause is bounded.
  Records that carry no authority still count toward the cap, so the witness admits to an identity's set only a
  membership signature by a root of the admitted membership it names as `prev` (a root it adds, only once a majority
  of those have signed the same record), and a freeze or contest signed by a root of the settled or pending
  membership; anything else is dropped on receipt. History is replayed from the
  first root, so the cap also bounds an identity's lifetime to about 85 settled changes (decision 9). A
  signature counts only if its
  root's key comes from a root record given (`checkRoot`) and its assertion covers that record's id. It never
  throws for any `records`; a malformed `ctx` is a programming error. `model/settled.mjs` is its specification in
  executable form: every state the model's explorer reaches, and every partial view of it, is translated into
  signed records and must give the model's answer.

- **R9 FRESH HEAD:** a **head** `{ identity, epoch, memberships, authority, revoked, at }` is signed by the
  membership witness (A4's `sig`): `membershipState` of every record the witness holds for the identity, at time
  `at`. `epoch` is the settled membership's epoch; `memberships` is the last settled membership id, followed by its
  pending successor's if there is one; the identity id is the first entry exactly when `epoch` is 1, and never the
  second (it is epoch 1's membership), and `epoch` is below 2^32, far inside exact arithmetic; `authority`
  is the sorted root ids with authority (R6); `revoked` is up to 64 sorted ids — delegation record ids or subject keys
  — revoked and not yet expired, so a revocation reaches verifiers as fast as a membership change, and revoking a
  subject key also revokes its renewals. The witness admits a revocation only when it is signed by a root with
  authority, or by the delegate for itself, and carries a delegate's revocation of itself as its subject key, so no
  delegate can add more than one entry. `headOf(state, at, revoked)` builds the body from R8's result; it gives none
  for an entry that is not an id or for more than 64 distinct ones, reading no further than the 65th. A head that
  cannot carry every live revocation is not signed (fail closed); the owner then replaces roots or lets delegations
  expire. The witness
  signs no head for an identity that is dead or frozen or in which no root has authority, and a verifier accepts none
  older than `maxStaleness`, so a stolen retired root is refused whatever records it is shown.
- **Head lag (residual):** a delegate chooses which head to present, so an anchored change, a freeze or a revocation
  reaches a verifier only once every older head has aged past `maxStaleness` — a day — unless the verifier passes
  `minHeadAt` or `lastHead` (F5), the newest head it has seen for the identity. A relying party that needs faster effect for a scope
  sets a smaller `maxStaleness`. Settlement retires the old membership's name: the id page renews delegations under
  the pending name before the window closes.

Why the witness: without a trusted time, a record signed late cannot be told from one signed early. Every set of
roots that was ever a majority of any epoch — including the first root alone, and roots long retired — could then
end or fork the identity at any time with one conflicting record.

What this gives (model-checked in [`model/settled.mjs`](model/settled.mjs), pinned in `tests/model/`, including every
partial view a network attacker can choose):
- **Three roots, a later one stolen:** the other two sign the next epoch without it, at once; the stolen root loses
  authority as soon as that record is anchored, and no thief move undoes it.
- **Two roots, a later one stolen:** the thief can neither take over nor end the identity.
- **A first or retired root stolen:** it can do nothing.
- **Every root the owner holds also stolen** (one root, or a majority): the thief can take over, but its new roots
  have no authority while pending; the owner can end the identity by contesting within the window; after it, the
  takeover is final.
- No view is ever forked; a freeze never makes an inactive identity active.
- **Limits:** a change that replaces every root (`{a}` → `{b}`), or most of them, leaves no or little authority until
  settlement. A lost single root cannot be replaced at all, since R1 needs its signature. "Two roots, a later one
  stolen" assumes the owner still holds the stolen root; if the theft also took it from the owner, the result is a
  stalemate that only a freeze ends. Three or more roots, in different sync ecosystems, avoid both.

Residuals:
- **The witness is trusted for membership.** A witness that backdates, anchors two rivals, or settles differently for
  different verifiers can fork an identity; one that refuses to anchor blocks recovery. Anchors and settlements are
  published to an append-only public log, so equivocation is visible; more than one witness is a later step.
- **Notification carries the window.** An owner who does not learn of a change within `CONTEST_WINDOW` — or whose
  contest a network attacker delays past it — loses the ability to contest. Where notifications go must itself be
  bound to a settled membership, so a thief cannot redirect them first. `CONTEST_WINDOW` is 72 hours (259,200 s), the
  override window that did:plc's recovery keys have used in practice.
- **Freshness (R9).** A verifier given only records, without a fresh head, would accept an older membership's roots
  — and a thief holding a retired root could mint new delegations under it. The guarantees above hold for a verifier
  that requires a head no older than `maxStaleness`; the residual is that window.

**revocation** — `{ identity, target, at }`, where `target` is a delegation's record id or a subject key. It is signed
by a root with authority (`sig = { root, assertion }`, as for membership records), or by the delegate for itself (`sig
= { signature }` by the subject key, as for claims); the witness revokes its own attestations in its log (decision 8).
The witness checks revocations and carries the live ones in heads (R9), which is how they reach verifiers; this
version of the core does not check revocation records itself. A revocation stays in heads until every delegation it
can affect has expired.

Reputation is computed from records. It is never signed as a record.

Research: [`delegation.md`](research/delegation.md), [`oidc-witness.md`](research/oidc-witness.md),
[`passkeys-and-recovery.md`](research/passkeys-and-recovery.md).

## 6. The decision function

```
const v = verifier({ rpId, origin, audience, witnessKeys, skew, maxLifetime, maxStaleness, maxClaimAge })
v.verifyDelegation({ delegation, root, head }, { now, scope, revoked, minHeadAt, lastHead })  // per call
  -> { ok: true, id, body } | { ok: false, reason }
v.verifyClaim({ claim, delegation, root, head }, { now, scope, request, revoked, minHeadAt, lastHead })
  -> { ok: true, id, body, delegation: { id, body }, until } | { ok: false, reason }
```

Configuration is set once, when the verifier is constructed, and cannot be changed per call: `rpId` and `origin`
are the id origin's; `audience` is this relying party's own origin (D5); `witnessKeys` are the membership witness's
pinned keys; `skew`, `maxLifetime` (D2), `maxStaleness` (R9) and `maxClaimAge` (C1, 300 s by default in
deployments) are the values of decisions 1, 3 and 7. Per call,
`delegation`, `root` and `head` are envelope texts: the delegation, the root record it names, and a head for its
identity. `scope` is the one scope the request needs; `revoked` lists further revoked record ids or subject keys the
relying party holds; `minHeadAt` (optional) refuses heads older than one it has already seen; `lastHead` (optional)
is the text of the newest head the relying party has accepted for the identity, which it keeps (decision 10).

- **F1 SYNCHRONOUS AND PURE:** no `await`, no clock, no storage, no network inside a decision.
- **F2 DENY BY DEFAULT:** every branch that is not an explicit accept is a reject. An unknown field is a reject.
- **F3 OPTIONS ONLY REMOVE TRUST:** no per-call input can make a record pass that the same verifier would reject with
  narrower inputs (more revocations). Tested as a monotonicity property.
- **F4 EXPIRY FIRST:** short-lived records do the revocation work; the revoked set is a backstop.
- **F5 CHECKS, IN ORDER:** `head` (the head does not open as a `head`, is not of its form, or is not signed as A4
  requires by a pinned key whose window holds both its `at` and `now`); `stale` (`at` is more than `maxStaleness`
  before `now`, more than `skew` after it, or before `minHeadAt` or `lastHead`'s `at`); `identity` (`lastHead` is
  for another identity); `equivocation` (the head cannot honestly follow `lastHead`, decision 10; when both have the
  same `at` and `lastHead` could honestly follow the head, `stale` instead, since a witness may sign two heads in one
  second); `root-record` (any `checkRoot`
  refusal); then D7's
  reasons for `delegation`, given
  the root record's key; `identity` (the head's identity is not the delegation's); `membership` (the delegation's
  membership is not among the head's `memberships`); `authority` (its root is not among the head's `authority`);
  `revoked` (its id or its subject key is in the head's `revoked` or the call's); `audience` (its `aud` is
  not `audience`); `scope` (`scope` is not among its
  `scopes`). Records that cannot be read are `head`. It never throws for any `delegation`, `root` or `head`; a
  malformed configuration, `now`, `scope` or `minHeadAt` (when given, a non-negative integer), a `lastHead` that is
  not a head of its form signed by a pinned key whose window holds its own `at` (it may have been signed by a key
  since retired), or
  a `revoked` that is not an array of ids, is a programming error (ignoring a malformed entry would fail open on
  revocation).

- **C1 CLAIMS (decision 1: ephemeral):** a **claim** `{ delegation, scope, request, at, data }` is a record signed by
  the delegation's subject key: its `sig` is `{ signature }`, an Ed25519 signature over the claim's signed bytes
  (K7). `delegation` is the id of the delegation it is made under; `scope` and `request` are the scope and the
  request it is for — `request` in the relying party's own canonical form (its method, URL and body hash, and a
  server nonce if it issues them, as DPoP does), so a claim seen in transit cannot be used on another request; `at`
  is the signer's time; `data` any object. `verifyClaim` takes the scope and request the relying party needs, and
  refuses, in order, with: V4's reasons for the claim (`envelope-encoding` too when the records cannot be read);
  `claim-shape` (keys other than the five, a field of the wrong
  form, or `sig` not as above); `claim-scope`; `claim-request`; then F5's reasons for the delegation;
  `claim-delegation` (the claim names another delegation); `claim-time` (`at` more than `maxClaimAge` before `now`,
  more than `skew` after it, or outside the delegation's window); then K5's signature reasons under the subject key.
  A claim is verifiable only while its delegation and head are. Replay within the window is the relying party's to
  refuse: the result carries the claim id and `until` (`at + maxClaimAge + 1`, the first time the claim is refused),
  so a store shared by every instance serving the audience keeps the id while `now < until`. A call whose `request`
  is not a string is a programming error. Every claim costs the full F5 check before its own signature; a relying
  party under load can rate-limit by delegation id. `data` is decoded data: frozen, with null prototypes.
- **C2 RECEIPTS (proposal; research/witness-tlog.md §5a):** a claim proves authority only while its delegation is
  live. A **receipt** `{ service, identity, delegation, claim, at }` makes an accepted claim attributable after that:
  signed by the receiving service's Ed25519 key (`sig = { signature, service }`, `service` that key in hex), it states
  that the service at origin `service` accepted the claim with record id `claim`, made under `delegation` for
  `identity`, at the service's time `at`. The service appends the receipt's envelope text to a transparency log; the
  log's entry is its UTF-8 bytes. `verifyReceipt({ receipt, checkpoint, proof, index, claim? }, ctx)` checks, in
  order: V4's reasons; `receipt-shape` (keys other than the five, an id not 64 lowercase hex, `service` not a
  canonical origin (O1), `at` not a non-negative integer, or `sig` not as above); `service` (the key is not one the
  caller pins for that origin); K5's signature reasons; `checkpoint` (the checkpoint does not verify under the
  caller's log configuration, with at least one cosigner); `inclusion` (the entry is not at `index` in the
  checkpoint's tree); `receipt-time` (`at` is later than the quorum's time, or than `now`, plus `skew`: a receipt
  cannot be accepted after it was logged, nor in the future); `service` (no pinned window for that key holds both `at` and the quorum's time, less
  `skew`: a retired key cannot mint receipts by backdating); `claim` (a claim is given and its record id is not
  `claim`, or it was made under another delegation). Within a key's window `at` is the service's word, bounded
  above by the quorum's time. A receipt is therefore kept with the checkpoint and proof obtained when it was logged,
  as a Sigstore bundle keeps its own: a checkpoint cosigned after the service key retired cannot vouch for it. It returns `{ service, identity, delegation, claim, at, existedBy }`, where `existedBy` is the
  quorum-th earliest cosignature time: unless the quorum lies, the receipt existed by then. A receipt is the
  service's statement, trusted as far as the caller trusts that service; it is not the identity owner's
  endorsement (§10).

The verifier needs no membership records: the head carries their result. The witness makes the head (R9); a delegate
fetches a fresh one and presents it with its requests, as OCSP stapling does.

**Root assertion checks** (the `sig` object of a root-signed record: `{ covers, authenticator_data,
client_data_json, signature }`; WebAuthn fields base64url):
- **W0 COVERAGE:** one assertion may cover several records, so one prompt can renew several delegations or sign a
  membership change together with the delegations that go with it. `covers` is a sorted list of 1–8 distinct record
  ids (lowercase hex) that contains this record's own id. A single record is a list of length one; there is no other
  form. The id page never puts two membership records with one `prev`, or a membership record and a contest, in one
  `covers`, and the witness refuses to anchor a record or contest that a counted signature shares that way with a
  rival or a contest it holds — so one prompt cannot both propose a change and end the identity. The verifier does
  not check this: discarding such signatures would let anyone who shows it the rival roll a settled change back.
- **W1 CLIENT DATA:** `type` is `"webauthn.get"`; `challenge` equals
  base64url(SHA-256(`UTF-8("muid/v1/assert\n")` ‖ the ids in `covers`, each followed by `"\n"`)) exactly — a domain
  distinct from the signed-bytes prefix `"muid/v1\n"`; `origin` equals the configured id origin exactly;
  `crossOrigin` is present and `false` (every browser measured emits it); `topOrigin` is absent. This separation
  holds only because nothing else on the id origin ever asks the passkey to sign: no login, no server challenge, no
  other ceremony (§8).
- **W2 AUTHENTICATOR DATA:** `rpIdHash` equals SHA-256(`rp_id`); UP and UV are set; AT, ED and the two reserved bits
  are clear
  and no bytes follow the 37-byte header; BS set implies BE set.
- **W3 SIGNATURE:** strict DER, verified as in §2, under the `pub` of the root the record names.
- **W5 NO COUNTER:** the signature counter is not consulted (synced passkeys report a constant).
- (There is no W4. A credential id is not covered by the assertion signature, so checking it would prove nothing.)
- **W6 CHECKS, IN ORDER:** `checkRootAssertion(sig, { record, rpId, origin, key })` returns `{ ok: true }` or
  `{ ok: false, reason }` and never throws for any `sig` (a context that is not four strings is a programming error).
  `sig` is first read as plain data through the encoder (§3), so anything the encoder refuses — an accessor, a Proxy
  that throws, a `null`, a float or a lone surrogate anywhere inside it — is `assertion-shape`.
  `record` is the id of the record being verified; `key` is the root's `pub` (K6). The first failure is the reason:
  `assertion-shape` (`sig` is not an object with exactly the four keys, three strings and an array);
  `covers` (W0); `assertion-encoding` (a WebAuthn field is not canonical unpadded base64url, or `client_data_json`
  is not UTF-8); `client-data` (W1's prefix is absent, or what follows it is not as W1 requires); `challenge`;
  `origin`; `auth-data-length`; `rp-id`;
  `user-presence`; `user-verification`; `auth-data-flags` (AT, ED or a reserved bit set, or BS without BE); then the
  K6 reasons for the signature, over `authenticator_data ‖ SHA-256(client_data_json)`. A throw from the hash library
  (possible only if code in the page patches built-ins it uses) is `sig-invalid`.
- **W1 in bytes:** `client_data_json` begins with exactly
  `{"type":"webauthn.get","challenge":"<challenge>","origin":"<origin>","crossOrigin":false` and the next byte is
  `}` (the last byte) or `,`. The four fields are compared as bytes. What follows may only be further members whose
  value is a string without escapes or control characters, `,"<key>":"<text>"`, with `<key>` of 1–64 characters of
  `[A-Za-z0-9_]` other than the prefix's four
  and `topOrigin`,
  then `}` as the last byte. Browsers add such members (Chromium sometimes adds one on purpose); nothing else is
  accepted, so no second JSON parser reads these bytes (§1).

Research: [`webauthn.md`](research/webauthn.md).

## 7. Storage interface (later step)

`get(key)` returns `{ value }` or `{ absent: true }`, or throws. A failed read is never reported as absence. A guard
test fails the build on any direct `indexedDB` or `localStorage` use outside the one adapter.

## 8. The id origin and machine onboarding (not core)

- The id origin is a dedicated host serving nothing else, with no subdomains. `rp_id` and the exact origin are
  deployment configuration, compared exactly; no suffix or wildcard rule exists anywhere.
- **I6 ONE CEREMONY:** the id page asks the passkey to sign only W1 challenges — never a server-chosen or login
  challenge — so no other use of the passkey can carry a muid challenge. It registers roots offering ES256 only
  (`alg: -7`), and never requests an authenticator extension (W2 refuses ED).
- **`rp_id` is permanent and public.** Every root record contains it, so every identity is publicly associated with
  that domain, and passkeys can never move to another. Related Origin Requests add origins but never change the
  `rp_id`. It is confirmed deliberately, as a branding and attribution decision, before the first real root.
- Root registration and every root-signed action happen in a top-level id-origin window (popup or redirect).
  Cross-origin iframe `create()` is not available in Safari or iOS browsers.
- **I1 SENDER:** a request is accepted only if `event.source` is this window's opener (or parent, for an iframe) and
  `event.origin` is a canonical origin (O1). `document.referrer` is never consulted.
- **I2 REPLY:** a reply is posted with `targetOrigin` equal to the request's `event.origin` — never `'*'` — and is not
  sent if the opener has navigated away.
- **I3 AUDIENCE FROM THE CHANNEL:** for a delegation an app requests, `aud` is the request's `event.origin`. An app
  cannot name a different audience. A machine delegation has no requesting app: the user chooses its `aud` on the id
  page, and the page shows it under I4.
- **I4 WHAT YOU SEE IS WHAT YOU SIGN:** the page renders every record in `covers` — a delegation's `aud`, `scopes`
  and `exp`; a membership change's added and removed roots; what a contest or freeze stops — from
  the exact payloads whose ids become the challenge; nothing is computed between display and signing.
- **I5 NO CACHED VERIFICATION:** every root assertion is a fresh ceremony with user verification; nothing is cached
  across actions.
- **U1 FIRST RUN:** one id-origin window and at most two user-verification prompts — passkey creation (which yields
  the root record, unsigned), then one assertion signing the app's first delegation.
- **U2 STEADY STATE:** at most one user-verification prompt per device per 30 days in ordinary use. Delegation
  lifetimes are chosen to meet U2 (decision 3), and renewal happens during a root ceremony the user is already
  in where possible. A delegation cannot be renewed without a root assertion; "silent renewal" does not exist.
- **U3 ONE ROOT IS ENOUGH TO START:** a first-time user has one root. Adding a second and third is encouraged later
  and never required to proceed.
- Machine onboarding: the machine generates its key first; the user opens the id origin and confirms the key
  fingerprint shown there matches the machine's. If a device code is used, it is one-time, short-lived and
  rate-limited, and the result is a delegation, never a bearer token. The `attest` scope is never granted this way.
- The witness hard-codes its issuers and their signing-key endpoints, follows no discovery redirect, and uses a
  distinct redirect URI per provider (GitHub returns no `iss`).

## 9. Open decisions

1. **Claims and time — decided: ephemeral in version 1.** A claim a delegate signs is verified on receipt against
   the verifier's `now`, and cannot be verified once its delegation has lapsed; a claim names the record id of the
   delegation it is made under. Durable claims (a witness countersignature over the claim's id and when it was seen)
   are a later layer. Any timestamp inside a record is chosen by its signer and proves nothing on its own.
2. **Recovery — decided: R1–R7, witness anchors and settlements with a contest window.** The model showed that
   without a trusted time any past majority can end an identity, and that anchoring the first record alone makes a
   thief's takeover of a one-root identity final at once. An independent review then showed that verifiers holding
   different records could fork; settlement and one anchor per epoch close that, and an explicit contest record keeps
   an honest owner from ending their own identity by accident.
3. **Lifetimes — decided: batched renewal.** Delegations to the user's own devices and to apps last at most 30 days
   (`maxLifetime` = 2,592,000 s); the id page gives machines at most 7 days. One passkey prompt renews every delegate
   at once (W0 covers up to 8 records), so expiry keeps doing the revocation work (F4) at the cost of a periodic
   prompt. `skew` is 60 s. Attestations last at most 365 days.
4. **Machine autonomy:** which scopes a machine may hold without per-action approval, and for how long.
5. **Boundary parser — decided: hand-written.** Every record type is checked by its own strict, hand-written code over
   the canonical decoder's output; a guard refuses any import other than noble and the core itself.
6. **`clientDataJSON` parsing — decided: the WebAuthn spec's limited (prefix) verification.** Chrome, Safari and
   Firefox all emit `{"type":…,"challenge":…,"origin":…,"crossOrigin":false` in that order, and Chromium deliberately
   appends an extra key to about one assertion in five (`RandDouble() < 0.2` in its source) so that verifiers do not
   match a template; a strict whole-text parse would reject those. The prefix rule checks the four fields byte for
   byte and accepts any remainder that closes the object.

7. **Freshness — decided: R9, with `maxStaleness` = 86,400 s (one day).** Without a fresh view of membership, a
   stolen retired or first root could sign delegations that a verifier accepts indefinitely; a network attacker only
   had to withhold records (`tests/model/R9-fresh-head.test.mjs` shows the attack and its absence with a head). The
   cost is that every delegate reaches the witness at least once a day; the residual is a day.
8. **Attestation binding — decided: one live binding per account, and a checkable request.** The witness keeps one
   live binding per `(provider, account)` and revokes the previous attestation when the account is bound again,
   publishing both in its log, so reputation can count an account once. An attestation will name the id of a
   root-signed request record, from which the OAuth `state` and OIDC `nonce` are derived, so A2 is checkable rather
   than trusted; that record and the witness protocol are specified with the witness. Anchors and settlements stay
   checked at their own `at`: a leaked retired witness key could sign backdated ones, and the append-only log is
   what shows them (residual).
9. **Long histories — decided: the bound stands for v1.** R8 replays from the first root, and `MAX_RECORDS` bounds
   each list, so an identity can make about 85 settled changes over its life; one that reaches the bound starts a new
   identity. A checkpoint (a witness-signed settled membership from which R8 starts) would lift the bound at the cost
   of trusting the witness for history before it; it is left to a later version.
10. **Witness equivocation — decided: the relying party's memory.** A verifier that remembers nothing cannot tell
   that the witness signed different heads for different relying parties
   ([`witness.md`](research/witness.md)). The head carries its settled epoch, and the call may pass the last head
   the relying party accepted for the identity (F5's `lastHead`, generalising `minHeadAt`). A head `h` cannot honestly
   follow a head `l` when `h`'s settled epoch, or the highest epoch it names (a pending successor's), is lower than
   `l`'s; when one id stands at different epochs in the two, or two ids at one epoch (each membership is of one epoch,
   and one anchor per `prev` gives each epoch one membership, R1, R3); or when authority (R6), which the memberships
   fix, does not follow them: unchanged while they stand, shrinking (to the shared roots) when a successor turns
   pending, growing when it settles with none pending after it. Such a pair is refused as `equivocation`, and the two
   signed heads are evidence; checked over every history the model's explorer reaches, an honest witness never produces one. Limits:
   it catches a split only within what one relying party sees, and a witness that jumps two epochs ahead between
   that party's heads escapes it (committing to keep the fork going for that party); a public log closes the rest.
   A witness key is retired by its window, never removed from `witnessKeys` while a relying party may hold a last
   head it signed (that head would become a programming error). Bounding backdated anchors needs time from outside the witness: a public log with at least one outside
   cosigner, the contest window starting at the cosigned time of the first checkpoint that includes the anchor.
11. **Freezes by incoming roots — decided: kept.** R2 lets any root of a pending record, new ones included, freeze it.
   None of the established systems ([`prior-art.md`](research/prior-art.md)) lets an incoming key lock anything. It is
   kept because a freeze only removes trust: it stops a change, never makes one, so the worst an incoming root can do
   is hold up the change that added it, and the owner who added it can supersede that change. In return an owner whose
   new device sees an unexpected change can stop it. The alternative, limiting a pending record's freeze to the roots
   of its `prev`, stays available if a case against this appears.
12. **Retaining subject-key revocations — decided: (b) now, (c) with the transparency log.** `exp − nbf` is
   bounded, but `nbf` is not, so a delegation signed today may become valid long after it was signed. A witness that
   drops a subject-key revocation once the delegations it knows of expire can therefore drop it too early: it may not
   know every delegation to that key. (b) The witness keeps a revocation for the life of the identity, except a
   root's revocation of a delegation id given with that delegation, kept until its `exp` plus `skew`; past 64 live
   entries no head is signed (R9, fail closed). (c) Once the witness is a transparency log, it logs every delegation
   it learns of, as certificate transparency logs every certificate, and relying parties may require a delegation to
   be logged, so the witness knows them all and the rest can lapse too. Option (a), first chosen — keep a
   revocation while the membership current when it was revoked, or its pending successor, has authority — was shown
   unsound by review: W0 lets the owner sign a change and the delegations under it in one prompt, so a delegation can
   exist under a membership before it is anchored, or under a chain of them, and no change of membership bounds what
   a revocation can affect.

## 10. What the reputation layer consumes (not core)

Sybil resistance and reputation live outside the core and must be able to change without reopening it. The core's
whole contribution is a set of verified facts:

- an identity id, its effective membership and that membership's roots (R6);
- each verified attestation: (`provider`, `account`, witness key, `nbf`, `exp`);
- each verified delegation: (`subject`, `aud`, `scopes`, `nbf`, `exp`);
- each verified claim and the delegation it was made under.

The reputation layer reads these and nothing else. It never holds a secret key, never verifies a signature itself, and
never writes a record the core trusts.

**Authority is not endorsement.** A delegation grants a key authority to act for an identity within its audience and
scopes. A claim made under it is attributable to that identity — software it authorised did this — but it is not a
statement that the identity's owner reviewed or endorses what was done. The reputation layer keeps the two apart.

**One identity is correlatable.** Every service that verifies an identity's records sees the same identity id, so
activity under it can be linked across services. For a public contributor history that is the purpose; someone who
wants activities kept apart uses separate identities.

**Memorable names (outside the core).** A root's key cannot be mined, but a name can be mined over an identity id:
find a nonce such that SHA-256(`"muid-name\n"` ‖ identity id ‖ nonce) begins with bits that map to a readable name.
That restores the original meaning of MUID — a memorable identifier whose cost is work — and puts a price on
creating identities, without touching custody. Its rules (domain, difficulty, word mapping) are specified with the
reputation layer.

## 11. Budget

Trusted core ≤ 2,000 lines, so that it stays reviewable in one sitting. The budget is raised deliberately when
clarity needs it, and never met by compressing comments. It was raised from 1,800 for the transparency-log checks
(`src/merkle.js`, `src/note.js`), whose adoption is to delete decision 10's rule.

## 12. Automated assurance

A tool counts only once it runs in CI and can fail the build. Each item lands with the first code it applies to,
never afterwards. Details and thresholds: `TESTING.md`; sources: [`assurance.md`](research/assurance.md).

**Gates running on every pull request**

| Gate | What it fails on |
|---|---|
| Unit + property tests (`node --test`, fast-check) | any invariant in this spec broken over adversarial generated inputs |
| Known-answer vectors, committed as data and pinned by hash | RFC 8785; NIST CAVP SHA-256; RFC 8032, Wycheproof Ed25519, ed25519-speccheck; Wycheproof ECDSA P-256 DER; W3C WebAuthn L3 §16 — with the loaded count asserted |
| Differential oracles | encoder ≠ reference JCS; Ed25519 and P-256 accepts that Node's crypto rejects; the membership state ≠ the executable model |
| Negative controls (broken twins) | a deliberately broken implementation, one per bug class, that its suite fails to reject |
| Mutation testing (Stryker, one job per module) | score below the break threshold |
| Coverage of the core | any uncovered line, branch or function |
| Core bans (a guard test) | in core files: `async`/`await`, clock and randomness reads, `JSON.parse` outside the decoder, imports other than noble and the core itself |
| Line budget, skipped tests, vector pinning, CI coverage of every test file and module | as named |
| Supply chain | install scripts (`npm ci --ignore-scripts`); unverified registry signatures; a dependency not pinned exactly, a lockfile entry from another registry or without sha512 integrity, an install script, or anything at runtime but the two noble packages |
| CI hardening | an action not pinned by commit SHA; a workflow with write permissions it does not need; any `pull_request_target` |
| CodeQL (`security-extended`, over `src/`) | any result; results are printed, not uploaded, so the token stays read-only |
| Semgrep (`.semgrep/core.yml`, image pinned by digest) | any match in `src/`, or a rule that stops firing on its own cases (`semgrep --test`) |
| Secret scanning (gitleaks, checksum-verified) | a secret in any commit, except findings reviewed in `.gitleaksignore` |
| Duplication (jscpd) | a clone in `src/` not in the reviewed `.jscpd-baseline.json` |
| SimpleWebAuthn differential | a root assertion accepted here and refused by SimpleWebAuthn; a known difference (where only it accepts) that changes |
| Release-age cooldown | a locked package published less than seven days ago (`.npmrc` `min-release-age` holds new choices to the same) |


**Scheduled, not gating**

Not yet scheduled:
- Long fuzz runs of `decode`, `verifyDelegation` and `verifyClaim` (fast-check at high iteration counts; Jazzer.js).
- The membership model (`model/settled.mjs`) at greater depth than the pinned tests, and models of the delegation,
  revocation and time-window rules, with their traces replayed against the verifier.
- An adversarial review agent against the core. Its findings go to a **private** security advisory, never a public
  issue.
- After every fix, a variant-analysis sweep for siblings of the bug.
