# muid — threat model and record spec

Status: draft 2. Layers 1–7 are implemented in `src/`; the verifier that composes them is not. Every invariant below
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
  signature, it is its 32 raw bytes, never its hex text — except in the W1 challenge, which is defined as text.
- **Time:** integer seconds since the Unix epoch. `now` is always a parameter, never read from a clock inside the core.
- **K3 NON-EXTRACTABLE DELEGATE KEYS:** in browsers a delegate key is generated as a WebCrypto Ed25519 key with
  `extractable: false`, so the secret never sits in JS memory and cannot be exported by any script, ours included. A
  machine's key lives in a file readable only by its owner (mode `0600`). Verification always uses noble, for one
  verdict everywhere. Where WebCrypto signs Ed25519 deterministically (Chromium, Firefox, Node), WebCrypto and noble
  must produce identical signature bytes for the same key and message — a differential test. Safari signs through
  CryptoKit, which randomises Ed25519 signatures, so there the test is that noble verifies what WebCrypto signs.
  (Custody code is not core, but this rule binds it.)
- **K7 ED25519 MESSAGES:** an Ed25519 key signs only `UTF-8("muid/v1\n") ‖ payload` (a record: the payload's
  `type` separates kinds, so a future claim is a record of its own type) or `UTF-8("muid/v1/<tag>\n") ‖` a
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
already written + 2L + 2 exceed the limit; a string, before it is copied, when the bytes already written + its length
+ 3 do; an object with k keys, when 6k + 1 does. Each bound is a true minimum, so none refuses anything that fits; the
array and string bounds are attained exactly, and tests pin a value that fits to the last byte.
**E5 ONE REASON:** a refusal carries exactly one reason code, and it is the same for every implementation. The top
level must be a plain object. Each container is checked on entry — cycle, then depth, then plainness (prototype and
internal slots), then width (E4), then shape (symbol keys, array holes and extra properties). An object's members are
then visited in canonical key order, each key checked (grammar, then data-property descriptor) before its value;
array elements in index order. The first violation found is the reason. Numbers are checked in the order non-finite,
`-0`, non-integer, unsafe integer. Reason codes: `top-level`, `key`, `symbol-key`, `accessor`, `non-enumerable`,
`non-plain`, `array-shape`, `cycle`, `depth`, `size`, `null`, `undefined`, `non-finite`, `negative-zero`, `float`,
`unsafe-integer`, `type`, `surrogate`, `syntax`, `non-canonical`, `exotic`. `exotic` covers anything an object throws
of its own while being read (a Proxy trap, a revoked Proxy) and a key listed without a descriptor; nothing other
than an `EncodingError` ever leaves `encode` or `decode`.
**E6 READ ONCE:** every prototype, key list, array length and property descriptor is read exactly once per encode, and
the value encoded is the value read. A Proxy cannot be detected in a browser; with E4 and E6 it cannot loop, read
twice or escape with a foreign error, and it can choose only what is encoded, as any caller can by building the
object. The bytes are what get signed.
**E7 OWN INTRINSICS:** the encoder uses only built-ins captured when its module loaded, called through a captured
`Reflect.apply`, and no iteration protocol; code that patches a built-in afterwards changes no result.
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
- **Signed bytes** = `UTF-8("muid/v1\n") ‖ UTF-8(payload)`. The verifier checks the signature over the payload bytes
  it received, then decodes those same bytes. It never re-serialises in order to verify.
- **Record id** = hex SHA-256 of the signed bytes. It excludes the signature (§2).
- **V1 VERSION:** `v` must equal 1. Any other value is rejected.
- **V2 TYPE:** the verifier is told which `type` it expects; a mismatch is rejected. Types form a closed list:
  `root`, `delegation`, `attestation`, `membership`, `freeze`, `contest`, `anchor`, `settlement`, `revocation`. Asking
  for any other type is a programming error, not a reject.
- **V3 ONE ALGORITHM PER TYPE:** the record type fixes the signature algorithm and the signer's role. Nothing in the
  record selects either.
- **V4 SHAPE BEFORE MEANING:** `open(text, type)` checks, in this order, and refuses with the first that fails:
  `envelope-encoding` (the text is not a canonical encoding), `envelope-shape` (keys other than above, `payload` not a
  string, `sig` not an object), `payload-size` (V5), `payload-encoding`, `payload-shape` (keys other than `v`,
  `type`, `body`, or `body` not an object), `version`, `type`. It returns `{ id, type, body, sig, payload }`, frozen,
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
other than `pub` and `rp_id`, or either not a string); `rp-id` (not the configured one); then K6's key reasons for
`pub`. Anyone can
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
- **D2 LIFETIME:** `exp − nbf ≤ MAX_DELEGATION`.
- **D3 DEPTH ONE BY TYPE:** only a root can sign a delegation (V3). There is no depth counter to get wrong.
- **D4 SUBJECT KEY:** the subject key satisfies K1 at issue and at verify.
- **D6 SUBJECT CONSENT:** a delegation is valid only together with an Ed25519 signature by `subject` over
  `UTF-8("muid/v1/accept\n") ‖` the delegation's record id as 32 raw bytes. Without it, a root could attach someone
  else's public key to its identity and have that key's signatures counted as its own.
- **D7 CHECKS, IN ORDER:** `checkDelegation(text, { rootKey, rpId, origin, now, skew, maxLifetime })` opens the
  envelope itself — so the id it checks is always the id of the bytes it was given — and returns
  `{ ok: true, id, body }` or `{ ok: false, reason }`, never throwing for any `text`. The context is read once.
  Reasons: V4's, for the envelope; `delegation-shape` (body keys other than the eight, or a field of the wrong form,
  or `sig` not `{ root, subject }`); `scopes`; `aud` (O1); `subject-key` (K1, via K5's key checks); `lifetime`
  (`exp ≤ nbf` or D2); `not-yet` and `expired` (D1); `root` (the root id of `rootKey` under `rpId` is not the body's
  `root`, so a caller cannot verify one root's assertion as another's); then W6's reasons for `sig.root` with this
  record's id; then
  `subject-consent` (any K5 signature reason for `sig.subject`). Whether `root` has authority under `membership`
  (R6), and whether the verifier's view is fresh (open decision 7), are the verifier's to decide (§6), not this
  check's. `skew` and `maxLifetime` are configuration (open decision 3).
- **D5 AUDIENCE:** `aud` is the origin of the relying party — the service that verifies the delegate's signatures. It
  is compared by exact string equality, after the origin itself is checked to be canonical (O1). For an app, the
  relying party is the app (I3). For a machine, it is the service the machine calls, chosen by the user on the id
  page (§8). There is no audience form other than an origin.
- **O1 CANONICAL ORIGIN:** `isCanonicalOrigin(x)` holds exactly for strings `https://<host>` or
  `https://<host>:<port>` where `<host>` is 2–127 dot-separated labels, each 1–63 characters of `[a-z0-9-]` not
  starting or ending with `-` and without `--` in positions 3–4 (so no IDN `xn--` label), the last label not all
  digits (so no IPv4 address), at most 253 characters; and `<port>` is 1–65535 in decimal without leading zeros, and
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
  `expired` (D1's window); `witness` (not a pinned key, or `now` outside that key's window — A1); then K5's signature
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

- **R1 CHANGE BY MAJORITY:** a membership record is valid only if signed by a strict majority of `prev`'s roots and by
  every root it adds. A root is retired by leaving it out.
- **R2 FREEZE BY ANY:** a freeze signed by any one root of the membership it names freezes it: delegations under it
  fail, and so do delegations under a pending successor of it. Only a settled successor (R4) moves past it. Freezing
  only removes trust, so any single root may do it.
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

- **R8 STATE, AS A FUNCTION:** `membershipState(records, ctx)`, with `records` grouped by type (`roots`,
  `memberships`, `contests`, `freezes`, `anchors`, `settlements`, each a list of envelope texts) and
  `ctx = { identity, rpId, origin, witnessKeys }`, verifies each record on its own — a record that does not verify
  carries no authority and is ignored — and returns `{ ok: true, dead: true }`, or
  `{ ok: true, dead: false, membership, epoch, roots, pending, authority, frozen }`, or `{ ok: false, reason }`
  with `unknown-identity` when no root record given is the identity's first root, or `records` when a list is
  longer than `MAX_RECORDS` (256) or cannot be read. Each text counts once, and a signer already counted for a
  record is not verified again, so the work a caller can cause is bounded. A signature counts only if its
  root's key comes from a root record given (`checkRoot`) and its assertion covers that record's id. It never
  throws for any `records`; a malformed `ctx` is a programming error. `model/settled.mjs` is its specification in
  executable form: every state the model's explorer reaches, and every partial view of it, is translated into
  signed records and must give the model's answer.

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
  bound to a settled membership, so a thief cannot redirect them first. The window's length is part of open decision 3.
- **Freshness (open decision 7).** A verifier that does not hold the latest settlement accepts the older membership's
  roots — and a thief holding a retired root can mint *new* delegations under the old membership, so delegation
  lifetimes do not bound this. Withholding records is enough. Every guarantee above holds only for a verifier whose
  view is fresh.

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

**What the verifier must add to the record checks** (each check above leaves these to it):
1. The root key passed to `checkDelegation` comes from a root record checked with `checkRoot`; it is looked up by the
   delegation's `root`, never found by trying keys (D7's `root` reason also refuses a mismatch).
2. R6: the delegation's `membership` is the last settled membership of its `identity`, or that membership's pending
   successor; neither is frozen; the root is in it (and, while pending, in both). For epoch 1, `membership` is the
   identity id, which must equal `identityOf(root)`; otherwise the membership record's `identity` must match.
3. Freshness: a head no older than `MAX_STALENESS` (open decision 7).
4. The delegation's id is not revoked.
5. D5 and scope: the delegation's `aud` is the verifier's own origin, and the requested scope is in `scopes`.
6. `skew` and `maxLifetime` are fixed configuration, never chosen per call.

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
- **W2 AUTHENTICATOR DATA:** `rpIdHash` equals SHA-256(`rp_id`); UP and UV are set; AT and ED are clear and no bytes
  follow the 37-byte header; BS set implies BE set.
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
  value is a string without escapes or control characters, `,"<key>":"<text>"`, with keys other than the prefix's four
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
  `event.origin` is a canonical origin (D5). `document.referrer` is never consulted.
- **I2 REPLY:** a reply is posted with `targetOrigin` equal to the request's `event.origin` — never `'*'` — and is not
  sent if the opener has navigated away.
- **I3 AUDIENCE FROM THE CHANNEL:** for a delegation an app requests, `aud` is the request's `event.origin`. An app
  cannot name a different audience. A machine delegation has no requesting app: the user chooses its `aud` on the id
  page, and the page shows it under I4.
- **I4 WHAT YOU SEE IS WHAT YOU SIGN:** the page renders `aud`, `scopes` and `exp` of every record in `covers`, from
  the exact payloads whose ids become the challenge; nothing is computed between display and signing.
- **I5 NO CACHED VERIFICATION:** every root assertion is a fresh ceremony with user verification; nothing is cached
  across actions.
- **U1 FIRST RUN:** one id-origin window and at most two user-verification prompts — passkey creation (which yields
  the root record, unsigned), then one assertion signing the app's first delegation.
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
   backdate a claim into the old window. Either (a) claims are **ephemeral**: verified on receipt against the
   verifier's `now`, and unverifiable once the delegation lapses; or (b) claims are **durable**: a time anchor fixes
   when the record existed, and authority is judged at that anchored time. A durable anchor is a witness
   countersignature over the record id and the time it was seen — another record checked against pinned keys. A
   verifier's own "first seen" time is not an option: different verifiers would reach different verdicts, against
   F1. Recommendation: (a) in version 1; (b) as a later layer for records that must outlive their delegation.
   Either way, a claim names the record id of the delegation it is made under, so a signature made under one
   delegation is never accepted under another. Revocation semantics follow from this choice: whether a revocation
   is retroactive, what `at` means, and whether a verifier may ever forget a revocation it has seen.
2. **Recovery — decided: R1–R7, witness anchors and settlements with a contest window.** The model showed that
   without a trusted time any past majority can end an identity, and that anchoring the first record alone makes a
   thief's takeover of a one-root identity final at once. An independent review then showed that verifiers holding
   different records could fork; settlement and one anchor per epoch close that, and an explicit contest record keeps
   an honest owner from ending their own identity by accident.
3. **Lifetimes, and the conflict they must resolve.** F4 wants delegations short so that expiry does the revocation
   work. D3 and U2 mean every renewal is a passkey prompt by a human. A machine that runs for weeks makes the two
   collide. Options: (a) long machine delegations, which make the revocation set the primary mechanism — then the
   spec must define how revocations and membership records reach verifiers, and a maximum staleness after which a
   verifier refuses; (b) batched renewal, where one prompt renews every delegate at once (W0), keeping F4 true at the
   cost of a periodic prompt. Values per kind of subject (own device, third-party app, machine); attestation lifetime;
   `skew`.
4. **Machine autonomy:** which scopes a machine may hold without per-action approval, and for how long.
5. **Boundary parser:** a schema library (valibot) or a hand-written strict parser for this small fixed set of types.
6. **`clientDataJSON` parsing — decided: the WebAuthn spec's limited (prefix) verification.** Chrome, Safari and
   Firefox all emit `{"type":…,"challenge":…,"origin":…,"crossOrigin":false` in that order, and Chromium deliberately
   appends an extra key to about one assertion in five (`RandDouble() < 0.2` in its source) so that verifiers do not
   match a template; a strict whole-text parse would reject those. The prefix rule checks the four fields byte for
   byte and accepts any remainder that closes the object.

7. **Freshness — needed before delegations are specified.** An independent review showed that without a fresh view
   of membership, a stolen retired or first root can sign delegations that a verifier accepts indefinitely, and a
   network attacker only has to withhold records. A verifier cannot tell "no newer settlement exists" from "none was
   shown to me" without something time-stamped. Recommendation: **R9 FRESH HEAD** — the witness signs, on request, a
   head `{ identity, settled, pending, at }`; a delegate presents a head no older than `MAX_STALENESS` together with
   its delegation (as OCSP stapling does), and the verifier checks the delegation's membership against the head
   rather than against whatever records it was given. The cost is that every delegate must reach the witness at least
   once per `MAX_STALENESS`. The value (hours to days) belongs with decision 3.
   Evidence: `tests/model/R9-fresh-head.test.mjs` shows the attack without a head and its absence with one.

8. **Attestation binding — from review, for decision.** (a) One provider account can be attested to many roots or
   identities, and a verifier holding one identity's records cannot see that; counting `(provider, account)` once
   needs the witness to keep one live binding per account and revoke the old one when it is re-bound, published in
   its log. (b) The record carries nothing a verifier can check for A2, so a dishonest witness could bind an account
   to a root that never asked; a `request` field naming a root-signed request (from which the OAuth `state` and OIDC
   `nonce` are derived) would make A2 checkable. (c) Anchors and settlements are checked against the witness key's
   window at their own `at`, so a retired key that leaks can sign backdated ones; the append-only log is what shows
   them. Recommendation: (a) and (b) before attestations carry weight in reputation; (c) stays a stated residual.

## 10. What the reputation layer consumes (not core)

Sybil resistance and reputation live outside the core and must be able to change without reopening it. The core's
whole contribution is a set of verified facts:

- an identity id, its effective membership and that membership's roots (R6);
- each verified attestation: (`provider`, `account`, witness key, `nbf`, `exp`);
- each verified delegation: (`subject`, `aud`, `scopes`, `nbf`, `exp`);
- each verified claim and the delegation it was made under.

The reputation layer reads these and nothing else. It never sees a key, never verifies a signature itself, and never
writes a record the core trusts.

**Memorable names (outside the core).** A root's key cannot be mined, but a name can be mined over an identity id:
find a nonce such that SHA-256(`"muid-name\n"` ‖ identity id ‖ nonce) begins with bits that map to a readable name.
That restores the original meaning of MUID — a memorable identifier whose cost is work — and puts a price on
creating identities, without touching custody. Its rules (domain, difficulty, word mapping) are specified with the
reputation layer.

## 11. Budget

Trusted core ≤ 1,500 lines. Going over is a design problem, not a reason to raise the budget.

## 12. Automated assurance

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
- The membership model (`model/recovery.mjs`) at greater depth than the pinned tests, and models of the delegation,
  revocation and time-window rules, with their traces replayed against `verify`.
- An adversarial review agent against the core. Its findings go to a **private** security advisory, never a public
  issue.
- After every fix, a variant-analysis sweep for siblings of the bug.
