# Delegation and capability designs

## Findings

### Designs

1. UCAN 1.0: a capability is subject + command + optional policy; commands are slash-delimited and a shorter path
   proves a longer one at segment boundaries (`/crypto` proves `/crypto/sign`, not `/cryptocurrency`); the `/` command
   "should be used sparingly"; "Every unique delegated capability MUST have equal or narrower capabilities from their
   delegator"; `aud` is the delegate; times are integer Unix seconds, `nbf` optional; no maximum delegation depth;
   revocation is a separate RECOMMENDED spec, "a last resort" and irreversible; UCAN "does not provide confinement".
   https://github.com/ucan-wg/spec/blob/main/README.md
2. UCAN 1.0 is inconsistent on `exp`: RECOMMENDED in prose, required in the payload table, and "If the token explicitly
   never expires, the `exp` field MUST be set to `null`". A chain is valid from the latest `nbf` to the earliest `exp`.
   https://github.com/ucan-wg/spec/blob/main/README.md
3. UCAN 0.x (JWT-based, npm `ucans`) used a different envelope and capability encoding from 1.0.
   https://cdn.jsdelivr.net/npm/@wovin/core@0.3.3/src/pubsub/UCAN%20Specs%20Overview.md . The `ucans` 0.10.0 store logs
   and skips a failing delegation chain instead of rejecting the UCAN.
   https://cdn.jsdelivr.net/npm/ucans@0.10.0/dist/src/store.ts
4. ZCAP-LD v0.4.0: `invocationTarget` URI, a child equals its parent's target or extends it by path or query suffix;
   `allowedAction` no less restrictive than the parent's; `controller` both invokes and re-delegates; `expires`
   required on delegated zcaps, a child may not outlive its parent, and verifiers "SHOULD NOT accept expirations more
   than three months out" because revoked zcaps must be stored until they expire; verifiers "SHOULD limit chain
   length" (no number); no clock-skew guidance; capabilities framed as a confused-deputy defence.
   https://w3c-ccg.github.io/zcap-spec/v0.4.0/
5. Nostr NIP-26: a `delegation` tag with delegator key, a conditions query string (`kind=N`, `created_at<T`,
   `created_at>T`) and a Schnorr signature over SHA-256 of `nostr:delegation:<delegatee>:<conditions>`; no revocation;
   marked `unrecommended` because it "adds unnecessary burden for little gain"; clients display delegated notes as if
   the delegator published them. https://github.com/nostr-protocol/nips/blob/master/26.md
6. did:plc: 1–5 ordered `rotationKeys` (secp256k1 or P-256) in descending authority; signing keys have no control over
   the DID; operations chained by CID via `prev`; a higher-priority key can override operations by a lower-priority
   key within 72 hours; signatures raw 64-byte low-S, and verifiers "must strictly reject non-canonical encodings and
   high-S values"; the PLC server is trusted not to serve the wrong fork. https://web.plc.directory/spec/v0.1/did-plc
7. RFC 8693: in delegation the actor keeps its identity, in impersonation it is indistinguishable from the subject;
   nested `act` claims "are informational only … not to be considered in access control decisions"; chain validation
   is left to implementations; short lifetimes recommended without numbers; an exchange does not change the validity
   of its input tokens. https://www.rfc-editor.org/rfc/rfc8693.html
8. KERI pre-rotation: each establishment event commits to a digest of the next key set, and pre-rotated keys "need
   never be exposed prior to their one-time use"; rotations can change witnesses and their threshold.
   https://datatracker.ietf.org/doc/html/draft-ssmith-keri ; https://arxiv.org/pdf/1907.02143 ;
   https://identity.foundation/keri/kids/kid0010.html

### Failures

9. Biscuit v1 (CVE-2022-31053, critical): the aggregate Γ-signature scheme was forgeable, allowing tokens with any
   access level; v2 replaced the algorithm. https://github.com/advisories/GHSA-75rw-34q6-72cr
10. Biscuit third-party blocks (GHSA-p9w4-585h-g3c7; CVE-2024-41949, CVE-2024-42350; biscuit-auth ≥ 4.0.0, fixed 5.0.0):
    the third party signed the previous block's public key and symbol-table keys supplied by the holder without checking
    them against the token, so an attacker could substitute their own key for the key a block was meant to require.
    https://osv.dev/vulnerability/GHSA-p9w4-585h-g3c7
11. X.509 name-constraint bypasses disclosed together on 14 October 2026, including pyca/cryptography CVE-2026-34073
    (DNS constraints checked against SANs but not the requested peer name), GnuTLS CVE-2026-3833 (case-sensitive
    comparison), wolfSSL CVE-2026-5263 (URI constraints "parsed but not enforced", fragment wildcards), AWS-LC
    (wildcard Common Name fallback), Go CVE-2026-33810 / GO-2026-4866 (case handling in wildcard lookup), OpenSSL
    PR #30319 (userinfo `@` scan past `/`, `?`, `#`), BoringSSL (wildcard vs excluded host, trailing-dot names); Mbed TLS
    treated non-critical name constraints as a feature request. https://openwall.com/lists/oss-security/2026/10/14/11
12. No published security advisory was found for UCAN implementations. A UCAN spec issue calls a proof whose audience
    does not match the next issuer a "principal alignment" violation (https://github.com/ucan-wg/spec/issues/130); the
    1.0 spec warns a chain can be structurally valid yet semantically invalid and "The executor MUST verify the
    ownership of any external resources at execution time" (https://github.com/ucan-wg/spec/blob/main/README.md).
13. Soft-fail revocation checking provides no security against an attacker who can block the check.
    https://www.imperialviolet.org/2011/03/18/revocation.html

### Time and revocation

14. UCAN: "Due to clock drift, time bounds SHOULD NOT be considered exact", with a ±60-second buffer; validation may
    happen on receipt and at execution; revoked CIDs and derivatives must be invalidated in caches.
    https://github.com/ucan-wg/spec/blob/main/README.md
15. NIP-26 recommends `created_at>` set to the current time to stop backdating and a bounded `created_at<`; both are
    values chosen by the signer of the event. https://github.com/nostr-protocol/nips/blob/master/26.md

### Test vectors

16. biscuit-auth 6.0.0 ships `examples/testcases.rs`, which generates the sample-token suite.
    https://docs.rs/crate/biscuit-auth/6.0.0/source/examples/testcases.rs
17. rs-ucan reports not testing against canonical fixtures and points to a proposed conformance set.
    https://www.github.com/ucan-wg/rs-ucan/issues/124

## Consequences for the spec

- D3: depth one is stricter than every surveyed design (findings 1, 4, 7 leave depth unbounded or advisory). Enforce it
  by type, not by a counter: a delegation verifies only if signed by a root key (ES256 passkey), and an Ed25519
  delegate key can never produce the delegation type (V2, V3). This excludes the "leaf accepted as CA" class.
- D3: a single level avoids RFC 8693's actor-chain ambiguity (finding 7) and the UCAN principal-alignment problem
  (finding 12).
- §5 delegation (`aud`): the X.509 wave (finding 11) failed on case, wildcards, trailing dots, URI parsing and unenforced
  constraint types. Compare `aud` byte for byte; define one canonical origin form at issue (lowercase; no trailing dot,
  userinfo, path or IDN variants; port policy stated). The canonical form is now D5.
- §5 delegation (`scopes`): sorted, distinct, flat strings with no prefix or wildcard semantics avoid UCAN command-prefix
  and X.509 subtree logic; any future hierarchy uses segment-boundary matching (finding 1).
- F2: a recognised-but-ignored field widens scope (wolfSSL, Mbed TLS in finding 11); "unknown field is a reject" should
  extend to any field the verifier parses but does not enforce. Finding 3's skip-and-log store is the opposite of
  deny by default.
- I4 (§8): the signer-side confused deputy (finding 10). The id-origin UI must show the user exactly the `aud`,
  `scopes` and `exp` that the passkey will sign, assembled and validated by the id origin.
- A2: the witness checks that the signed OAuth `state` belongs to its own session (finding 10 is the failure where a
  signer signs context it did not verify).
- D1: skew applies on the `nbf` side only and `exp` is exact; UCAN's two-sided buffer (finding 14) can extend a
  token's life. §9 decision 3: a `skew` of 60 s or less matches UCAN.
- D2, §9 decision 3: `exp` mandatory and finite (contrast finding 2). Choose `MAX_DELEGATION` so the revoked set is bounded:
  a revocation need be kept only until its target's `exp`, then pruned (ZCAP's rationale, finding 4).
- F4, §7: "revoked set unavailable" must be distinct from "not revoked" (finding 13).
- §4: revocation targets a record id that excludes the signature; did:plc must mandate low-S because its ids hash
  signatures (finding 6), which passkey ES256 signatures cannot satisfy.
- §5 revocation (`at`): a record-internal time is the signer's claim, never evidence of when something happened
  (finding 15).
- F1: a decision is only as fresh as the `now` and `revoked` the caller passes; re-verify at use, not only at receipt
  (finding 14).
- R1–R8 (§5): did:plc's priority-ordered keys with a 72-hour override window (finding 6) are a working recovery pattern, at
  the cost of trusting whoever orders records. A KERI-style commitment to a hash of a recovery key in the root record
  (finding 8) is an option; passkeys cannot be pre-generated unexposed, a printed recovery code can. Not yet in spec.
- §12: commit vectors as data in the Biscuit style (finding 16), generated by a script, each naming the rule it
  exercises (E1–E3, V1–V3, D1–D6, A1–A2), including: `aud` case, trailing-dot and port variants; unsorted or duplicate
  scopes; a delegation signed by a delegate key; high-S root signatures that verify with unchanged record ids; an
  unknown field; `exp` equal to `now`; `nbf` beyond skew; a revoked target; a type mismatch.
- §12: attenuation at depth one is trivial; what is worth model-checking is the D1–D6, V1–V3 decision
  over a small domain (type, signer kind, `aud`, scope, time), e.g. that no delegate-signed record verifies as a
  delegation.

## Unverified

- UCAN 0.x field details (`att: [{with, can}]`, `prf`, `my:`/`as:` schemes, one token for delegation and invocation).
- Biscuit block chaining (each block signed by the key in the previous block), sealed tokens, revocation ids derived
  from block signatures, time via an authorizer `time()` fact. If revocation ids are signature-derived, strict Ed25519
  is non-malleable, so this is safe for Biscuit where it would not be for ECDSA.
- biscuit-java CVE-2024-41948, third-party block support "inoperating" in 3.x (search snippet only).
  https://advisories.gitlab.com/pkg/maven/org.biscuitsec/biscuit/CVE-2024-41948
- Biscuit sample suite layout (`samples/current/samples.json`, test006 reordered blocks, test020 sealed token)
  (third-party summary). https://deepwiki.com/eclipse-biscuit/biscuit/4.1-sample-tokens
- In finding 11's post: rustls/webpki CVE-2026-93600 and CVE-2026-93601 (identifiers look unusual), the OpenSSL and
  BoringSSL dates and commit, and the open items (Go IPv4-mapped IPv6, NSS, LibreSSL, s2n-tls); check against the post.
  CVSS integrity impact for CVE-2026-33810 differs between secondary sources (https://stack.watch/vuln/CVE-2026-33810/ ;
  https://fieldguide.lutrasecurity.com/CVE-2026-33810).
- Macaroons (chained HMAC, first- and third-party caveats, bearer with no audience, unknown caveats fail closed);
  SPKI/SDSI RFC 2693 (5-tuple, one propagate bit, tag intersection); X.509 RFC 5280 (`pathLenConstraint`,
  `nameConstraints`); Keybase sigchains (append-only, Merkle root anchored to a blockchain, hard-coded exceptions for
  historical bad links).
- Classic X.509 chain bugs: CryptoAPI `basicConstraints` (2002), iOS CVE-2011-0228, OpenSSL CVE-2015-1793,
  CVE-2022-3602/3786, BetterTLS Common Name fallback findings.
- Time conventions: JWT leeway "usually no more than a few minutes", Kerberos 5-minute skew, CA backdating of
  notBefore.
- Web PKI revocation: OCSP soft-fail in browsers, Let's Encrypt ending OCSP (2025) with ~6-day certificates, CA/B Forum
  SC-081 (47-day maximum by 2029), CRLite/CRLSets.
- KERI unrecoverable cases (unresolvable duplicity; attacker obtaining pre-rotated keys first) (informal source).
  https://wiki.hyperledger.org/x/6Zx6Ag . Contents of ToIP KERI v1.1 (2026-01-21).
  https://trustoverip.org/wp-content/uploads/KERI-V1.1-2026-01-21.pdf
- Formal work: SPKI/SDSI logics (Abadi 1998; Halpern and van der Meyden; Li and Mitchell 2003), ARMOR (IEEE S&P 2024),
  CERES, Frankencerts (S&P 2014). Whether Biscuit or UCAN have mechanised proofs of attenuation.
- Conformance suites: ucan-wg/conformance-tests status, C2SP x509-limbo, bluesky-social/atproto-interop-tests (high-S
  rejection vectors).
