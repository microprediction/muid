# WebAuthn assertion verification

## Findings

### Specification (WebAuthn Level 3)

1. WebAuthn Level 3 is a W3C Recommendation dated 25 August 2026, with "no substantive changes since the Candidate
   Recommendation Snapshot of 26 May 2026". https://www.w3.org/TR/webauthn-3/ ;
   https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
2. §7.2 relying-party steps, in order: response type; credential id ∈ `allowCredentials` if non-empty; credential and
   `userHandle` binding to an account; UTF-8 decode of `clientDataJSON` with any leading BOM stripped; parse with an
   "implementation-specific JSON parser"; `type === "webauthn.get"`; `challenge` equals the base64url of the expected
   challenge; `origin` is "an origin expected by the Relying Party"; `crossOrigin`/`topOrigin` only if cross-origin
   iframe use is expected; `rpIdHash` equals SHA-256 of the RP ID; UP set; UV set if and only if required ("Otherwise,
   ignore the value of the UV flag"); BS not set unless BE set; stored BE/BS comparison (stateful); signature over
   `authData ‖ SHA-256(cData)`; signCount comparison (a regression is "a signal, but not proof" of cloning, handling is
   "Relying Party-specific"); extensions processed "as required by the RP", unsolicited ones ignored or rejected;
   stored state updated. https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion
3. §5.8.1.2 Limited Verification Algorithm, for verifiers without a full JSON parser: `clientDataJSON` must begin with
   exactly `{"type":` + CCDToString(type) + `,"challenge":` + CCDToString(b64url(challenge)) + `,"origin":` +
   CCDToString(origin) + `,"crossOrigin":` + (`true`[+ `,"topOrigin":`…] | `false`), followed by `}` or `,`.
   https://www.w3.org/TR/webauthn-3/#clientdatajson-verification
4. CollectedClientData: `type`, `challenge`, `origin` required; `crossOrigin`, `topOrigin` optional, `topOrigin` "set
   only if … crossOrigin is true"; `tokenBinding` is "[RESERVED]". Parsers must be "tolerant of unknown keys and of any
   reordering of the keys". `type` exists "to prevent certain types of signature confusion attacks".
   https://www.w3.org/TR/webauthn-3/#dictdef-collectedclientdata
5. §13.4.9: the RP "MUST NOT accept unexpected values of origin"; an application served only at one origin "SHOULD
   require origin to exactly equal" it; subdomain matching must be structural; when `topOrigin` is present the RP "MUST
   validate that its value is expected". https://www.w3.org/TR/webauthn-3/#sctn-validating-origin

### Server libraries

6. Measured locally (source read, `@simplewebauthn/server` 14.0.3, `verifyAuthenticationResponse`): async throughout
   (hashing, RP ID match and `subtle.verify` are awaited); requires `id === rawId`; `JSON.parse` on clientDataJSON;
   type exact or caller list; challenge exact `===` or caller-supplied async function; origin exact or list
   `includes`; `topOrigin` with `crossOrigin: false` throws; authData parser requires ≥ 37 bytes and throws on
   leftover bytes; UV required by default; counter regression throws; BS without BE throws. It does **not** compare
   `response.id` with the stored credential id and has no `allowCredentials` parameter. With `advancedFIDOConfig` set it
   checks only UV for `'required'` and **no flags at all** for `'preferred'`/`'discouraged'`.
   https://github.com/MasterKale/SimpleWebAuthn
7. py_webauthn checks `id == raw_id`, exact origin or list membership, rpIdHash, UP; `require_user_verification`
   defaults to **False**; counter regression raises.
   https://github.com/duo-labs/py_webauthn/blob/master/webauthn/authentication/verify_authentication_response.py
8. go-webauthn compares the challenge in constant time, normalises origins to scheme://host[:port], makes UP and UV
   configurable booleans, and on counter regression sets `CloneWarning = true` without failing.
   https://github.com/go-webauthn/webauthn/blob/master/protocol/client.go ;
   https://github.com/go-webauthn/webauthn/blob/master/protocol/assertion.go ;
   https://github.com/go-webauthn/webauthn/blob/master/webauthn/authenticator.go
9. Yubico java-webauthn-server matches origins through `OriginMatcher.isAllowed(…, allowOriginPort,
   allowOriginSubdomain)`, enforces "Backup eligibility must not change", and fails on counter regression only when
   `validateSignatureCounter` is set.
   https://github.com/Yubico/java-webauthn-server/blob/main/webauthn-server-core/src/main/java/com/yubico/webauthn/FinishAssertionSteps.java
10. webauthn4j has separate origin and top-origin verifiers, configurable UP/UV (`UPUVFlagsVerifier`), and a pluggable
    counter-regression handler.
    https://github.com/webauthn4j/webauthn4j/blob/master/webauthn4j-core/src/main/java/com/webauthn4j/verifier/AuthenticationDataVerifier.java
11. Synchronous verifiers exist outside JS: go-webauthn, py_webauthn, java-webauthn-server and webauthn4j each implement
    §7.2 in their own code over a platform crypto library (sources as in findings 7–10).

### Advisories (2024–2026)

12. CVE-2026-30964 / GHSA-f7pm-6hr8-7ggm (web-auth/webauthn-framework 5.2.0–<5.2.4): allowed origins were reduced to
    `parse_url(...)['host']` and matched on host alone; scheme and port differences ignored.
    https://osv.dev/vulnerability/GHSA-f7pm-6hr8-7ggm
13. GHSA-22w3-693w-x895 (webauthn-rs-core < 0.5.5, low): origin checked against the RP ID with `ends_with` without a dot
    boundary (`hermit-crab.example` passed for `crab.example`), when `allow_subdomains_origin` was enabled.
    https://github.com/kanidm/webauthn-rs/security/advisories/GHSA-22w3-693w-x895
14. GHSA-vc6p-58xv-r749 (NuGet Fido2 ≤ 4.0.1, fixed 4.1.0): counter check written as `signCount > 0 && signCount <=
    stored`, which "short-circuits whenever the assertion-side count is 0", so a clone sending 0 bypassed detection. The
    advisory states SimpleWebAuthn, py_webauthn, webauthn4j and go-webauthn implement the OR condition correctly.
    https://github.com/passwordless-lib/fido2-net-lib/security/advisories/GHSA-vc6p-58xv-r749
15. GHSA-6hxq-p678-4hr2 (@simplewebauthn/server < 13.3.2, low): attestation certificate path validation stopped at the
    first self-signed certificate, which could be attacker-supplied. Registration only.
    https://osv.dev/vulnerability/GHSA-6hxq-p678-4hr2 . Two further SimpleWebAuthn advisories (2026-09-13, medium):
    attestation certificates triggering server-side HTTP requests (GHSA-j3h4-m3m2-7p7j) and rejected registrations
    poisoning a process-wide CRL cache (GHSA-2g3p-m8c9-hhwh); both registration/attestation.
    https://github.com/MasterKale/SimpleWebAuthn/security/advisories
16. GHSA-gw6g-q29j-3jvp (Fido2 < 4.3.1, critical): the metadata BLOB JWS was verified against all `x5c` keys while only
    `x5c[0]` was chain-validated. GHSA-jc6v-cf3v-w2fm (Fido2, high): DoS, SSRF and metadata validation bypass.
    https://github.com/passwordless-lib/fido2-net-lib/security/advisories
17. Keycloak: CVE-2025-12150, attestation policy bypass via `fmt: "none"` (https://osv.dev/vulnerability/GHSA-7g5x-9c4v-4w5r);
    CVE-2026-37982, action-token replay registering an attacker's authenticator to a victim account
    (https://osv.dev/vulnerability/GHSA-w4p5-rfh6-cwrv); CVE-2026-8830, registration policy bypass via client-side
    JavaScript (https://osv.dev/list?q=keycloak-services).
18. Other: CVE-2024-39912 username enumeration and GHSA-gq4g-fpc9-vjfq predictable fake credentials with an empty secret
    in web-auth/webauthn-lib (https://osv.dev/vulnerability/GHSA-875x-g8p7-5w27); GHSA-g3qj-j598-cxmq, heap over-read in
    `cbor-extract` during attestation parsing in npm fido2-lib (https://osv.dev/vulnerability/GHSA-g3qj-j598-cxmq).
19. OSV returned no advisories for PyPI `webauthn`, PyPI `fido2`, `github.com/go-webauthn/webauthn`,
    `github.com/duo-labs/webauthn`, `com.yubico:webauthn-server-core`, `com.webauthn4j:webauthn4j-core`,
    `@passwordless-id/webauthn` or RubyGems `webauthn`; the corresponding GitHub repository advisory listings were empty.
    https://api.osv.dev/v1/query

### COSE keys and vectors

20. Measured locally (source read, `@simplewebauthn/server` 14.0.3, `verifyEC2.js`): requires `alg`, `crv`, `x`, `y`;
    selects the hash from the stored key's `alg`; does not check x/y lengths itself; relies on WebCrypto JWK import for
    point validation. `parseAuthenticatorData.js` patches a known-malformed EdDSA COSE key byte sequence, showing
    authenticator COSE output is not always well-formed. https://github.com/MasterKale/SimpleWebAuthn
21. Wycheproof `ecdsa_secp256r1_sha256_test.json` (DER, 484 tests) is the matching vector set for ES256; results in
    [signatures.md](signatures.md). https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/ecdsa_secp256r1_sha256_test.json

## Consequences for the spec

- §8.1: the advisories in the assertion path (findings 12–14) are origin matching and counter logic; the heavy
  surface (findings 15–18) is registration and attestation. Option (a) needs only the stateless subset of §7.2, and
  findings 6 and 11 show option (b) would bring SimpleWebAuthn's option surface (UP skipped under `advancedFIDOConfig`,
  challenge callback, lenient DER, no credential-id check) into the trust decision and split it across F1.
- W0–W6 (§6) checklist, each with no option that weakens it: `rawId` equals `root.cred_id`; strict canonical base64url for
  every field (§2); fatal UTF-8 decode, BOM stripped; `type === "webauthn.get"`; challenge equals
  b64url(SHA-256(signed bytes)) exactly, no prefix or substring match; origin equals the id origin exactly; reject
  `crossOrigin === true` and any `topOrigin`; authData ≥ 37 bytes with no leftover bytes; rpIdHash equals
  SHA-256(`rp_id`) from the root record; UP = 1 and UV = 1; BS ⇒ BE; AT = 0; ED rejected or ignored by a stated policy;
  signature verified as in [signatures.md](signatures.md) with a throw mapped to reject.
- F3: UP and UV are configurable in go-webauthn, webauthn4j and SimpleWebAuthn (findings 6, 8, 10) and the UV default
  differs between libraries (findings 6, 7); the core hard-codes both as required.
- §8: origin and RP ID are compared by exact equality; findings 12 and 13 are the failure modes of host-only and
  suffix matching.
- §9 decision 6, §12 (`JSON.parse` ban): clientDataJSON is parsed either by the single boundary parser, which must reject
  duplicate `type`/`challenge`/`origin` keys (`JSON.parse` keeps the last), or by the Limited Verification Algorithm
  (finding 3), which needs no JSON parser but assumes browser key order.
- W5: signCount and stored BE/BS comparisons are stateful (finding 2) and meaningless for records verified
  later by third parties; §1 should declare them out of scope for record verification. If a counter rule is ever added,
  it uses the spec's OR condition and is tested at (0, n > 0) (finding 14).
- §5 root, V3: COSE is parsed once, at root creation: require kty = 2, alg = −7, crv = 1, |x| = |y| = 32; build
  `0x04 ‖ x ‖ y`; validate; store 65 bytes. The verify path never reads COSE, and `alg` never selects anything
  (finding 20).
- §12 differential oracle (SimpleWebAuthn): compare `rawId` with `root.cred_id` in the harness; never set
  `advancedFIDOConfig`; `requireUserVerification: true`; `expectedType: 'webauthn.get'`; exact `expectedOrigin` and
  `expectedRPID`; no `expectedTopOrigin`; `expectedChallenge` = b64url(SHA-256(signed bytes)); `credential.counter = 0`.
  Keep a committed divergence register (lenient DER, credential id, counters, extensions) so a new divergence fails the
  build.
- §12 generated vectors: a software P-256 authenticator (fast-check) emits valid assertions in low-S and high-S forms;
  single-field mutations must all be rejected: each flag bit (UP, UV, BE/BS, AT, ED); rpIdHash byte; type
  `webauthn.create`; challenge off by one byte, padded, standard alphabet, prefix or suffix; origin with other scheme,
  port, trailing slash, uppercase, subdomain, `evil-<host>`, `<host>.evil`; `crossOrigin: true`; `topOrigin`; BOM;
  invalid UTF-8; duplicate, reordered and extra keys; truncated or extended authData; signature over the wrong data or
  double-hashed; wrong credential id.
- §12 negative controls: verifiers that skip the challenge, use `origin.endsWith`, use `lowS: true`, or use the AND-form
  counter (finding 14) must each fail the suite.
- §12 mutation testing: every check in the W0–W6 (§6) checklist needs a test that kills its removal.

## Unverified

- Chrome has been reported to sometimes add a field to clientDataJSON to deter prefix-matching parsers; current Chrome,
  Safari and Firefox key order, and whether `crossOrigin` is always emitted, are unconfirmed. Both matter for the
  Limited Verification Algorithm.
- Whether L3 §6.1.1 / §6.1.3 add guidance on synced passkeys reporting signCount 0 (widely reported; see
  [passkeys-and-recovery.md](passkeys-and-recovery.md) for a primary report of constant counters).
- Yubico `allowOriginPort` and `allowOriginSubdomain` default to false; exact subdomain/port semantics of Yubico
  `OriginMatcher`, webauthn4j `OriginVerifierImpl` and go-webauthn `IsOriginInHaystack`.
- No mature JS library verifies WebAuthn assertions synchronously on noble or another non-WebCrypto library (search
  not exhaustive; `@passwordless-id/webauthn`, Hanko and Deno libraries not checked).
- No published advisory found for skipped challenge checks, substring/regex clientDataJSON parsing or COSE `alg`
  confusion in a major server library; older advisories (2019–2023) outside OSV and repository listings not searched.
- Paths and contents of assertion fixtures in the SimpleWebAuthn and py_webauthn test suites; whether the FIDO
  Alliance server conformance tools can be run against a library rather than a deployed server.
