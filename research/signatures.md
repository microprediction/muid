# Signatures: ECDSA P-256 (WebCrypto, noble) and Ed25519

## Findings

### ECDSA P-256

1. WebCrypto ECDSA signatures are raw `r ‖ s` (IEEE P1363); `verify` returns false unless the signature is exactly
   2 × 32 bytes. The specification says nothing about low-S. https://w3c.github.io/webcrypto/
2. Measured locally (Node v26.8.1 WebCrypto, P-256/SHA-256, 64 trials): `sign` emitted high-S in 26 of 64 trials; all 64
   flipped signatures `(r, n − s)` verified. Rejected: r = s = 0, s = 0, r = n, a 63-byte signature.
   https://w3c.github.io/webcrypto/
3. Measured locally (source read, `@noble/curves` 2.4.0, `src/abstract/weierstrass.ts`): ECDSA `lowS` defaults to true
   for both sign and verify; verify defaults to `format: 'compact'` and `prehash: true`. The docs: "`lowS`: (default:
   true) prohibits signatures with `sig.s >= CURVE.n/2n` … Setting `lowS: false` allows to create malleable
   signatures". https://github.com/paulmillr/noble-curves
4. noble-curves v2 migration notes: methods expect the unhashed message (old behaviour `{prehash: false}`); low-S by
   default (old `{lowS: false}`); "der format must be explicitly specified in `{format: 'der'}`"; Signature instances are
   no longer accepted by verify. https://github.com/paulmillr/noble-curves#upgrading
5. Measured locally (source read and run, `@noble/curves` 2.4.0, Node v26.8.1): `verify` validates options, then calls
   `validateSigLength(signature, format)` outside its try/catch, so a 71-byte DER signature passed without
   `format: 'der'` throws "expected Uint8Array of length 64, got length=71" rather than returning false. Inside the try
   it parses the signature, runs `Point.fromBytes(publicKey)` (with `assertValidity()`), rejects the identity point,
   applies `if (lowS && sig.hasHighS()) return false`, runs the SEC1 4.1.4 check, and returns false on any inner
   exception. https://github.com/paulmillr/noble-curves
6. Measured locally (source read, `@noble/curves` 2.4.0, `src/abstract/der.ts`): total length capped at 2·32+16 bytes;
   tag must be 0x30; leftover bytes rejected at SEQUENCE and INTEGER level; long-form length rejects indefinite length,
   more than 4 length bytes, a zero leading length byte, and non-minimal encoding (< 128 in long form); INTEGERs reject
   empty, negative (high bit set) and unnecessary leading zero, capped at 33 bytes; the `Signature` constructor enforces
   r, s ∈ [1, n − 1]. https://github.com/paulmillr/noble-curves
7. Measured locally (source read, `@noble/curves` 2.4.0): `Point.fromBytes` accepts 33-byte compressed or 65-byte
   `0x04 ‖ x ‖ y`, checks the point is on the curve, and `assertValidity` rejects the identity, out-of-field
   coordinates and non-subgroup points. https://github.com/paulmillr/noble-curves
8. Measured locally (Node v26.8.1, `@noble/curves` 2.4.0, Wycheproof `testvectors_v1/ecdsa_secp256r1_sha256_test.json`,
   484 tests, `format: 'der'`): with `lowS: false`, 484 pass, 0 fail (the file has no "acceptable" cases); with
   `lowS: true`, 413 pass, 71 fail, and every failure is a valid high-S signature (e.g. tcId 2, 3, 7, 299).
   https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/ecdsa_secp256r1_sha256_test.json
9. Measured locally (Node v26.8.1; same message and key, mutated DER; noble 2.4.0 `{format: 'der', lowS: false}` vs
   `@simplewebauthn/server` 14.0.3 `verifySignature` with a COSE EC2 key):

   | Case | noble | SimpleWebAuthn |
   |---|---|---|
   | valid | true | true |
   | high-S | true | true |
   | trailing 0x00 after SEQUENCE | false | **true** |
   | non-minimal long-form SEQUENCE length (0x81 xx) | false | **true** |
   | long-form INTEGER length | false | **true** |
   | r + n (33-byte r) | false | throws |
   | raw 64-byte compact passed as DER | false | throws "Too big integer" |
   | extra leading zero on r | false | throws |

   A "negative r without pad" case was inconclusive (the sampled r had its high bit clear).
   https://github.com/paulmillr/noble-curves ; https://github.com/MasterKale/SimpleWebAuthn
10. Measured locally (source read, `@simplewebauthn/server` 14.0.3, `helpers/iso/isoCrypto/unwrapEC2Signature.js`): DER
    is parsed with `@peculiar/asn1-schema` `AsnParser.parse(signature, ECDSASigValue)`; short integers are left-padded
    to 32 bytes; one leading 0x00 is stripped only if the next byte has its high bit set, otherwise it throws "Invalid
    signature component length". The EC2 verifier then calls `WebCrypto.subtle.verify` after JWK import.
    https://github.com/MasterKale/SimpleWebAuthn
11. A WebAuthn assertion signature is over `authenticatorData ‖ SHA-256(clientDataJSON)` (§7.2); ES256 hashes that
    concatenation once more. With noble's default `prehash: true` the raw concatenation is passed; passing a
    precomputed digest without `prehash: false` double-hashes and every signature fails.
    https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion ; https://github.com/paulmillr/noble-curves#upgrading
12. CVE-2022-21449: JDK 15–18 ECDSA accepted r = s = 0; the java-webauthn-server README notes it enables authentication
    bypass. https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/ ; https://github.com/yubico/java-webauthn-server
13. did:plc requires raw 64-byte low-S signatures and strict rejection of high-S and non-canonical encodings, because
    malleability would change an operation's content id. https://web.plc.directory/spec/v0.1/did-plc

### Ed25519

14. RFC 8032 permits either the cofactored or cofactorless verification equation; implementations disagree on edge
    cases (small-order and mixed-order points, non-canonical encodings, S ≥ ℓ). "Taming the many EdDSAs"
    https://eprint.iacr.org/2020/1244 ; https://hdevalence.ca/blog/2020-10-04-its-25519am
15. ZIP-215 fixes a permissive, cofactored validation rule for consensus use. https://zips.z.cash/zip-0215
16. The WebCrypto specification notes for Ed25519 small-order point checks that "Not all implementations perform this
    check" (issue 423), so verdicts can differ across browsers. https://w3c.github.io/webcrypto/
17. Measured locally (source read, `@noble/curves` 2.4.0, `src/abstract/edwards.ts`): `verify` defaults to
    `zip215: false`; strict decoding requires y < p; `if (!zip215 && A.isSmallOrder()) return false` rejects a purely
    small-order public key A but **not** a mixed-order A; S < ℓ is checked inside `multiplyUnsafe`.
    https://github.com/paulmillr/noble-curves
18. Wycheproof `testvectors_v1/ed25519_test.json`: 210 tests (117 valid, 64 invalid, 29 acceptable). All 29
    "acceptable" vectors are SmallOrderPublicKey (8) or MixedOrderPublicKey (21), bugType `CAN_OF_WORMS`; they satisfy
    the cofactored equation and implementations "may reject them under a stricter public-key policy".
    https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/ed25519_test.json
19. ed25519-speccheck gives 12 edge vectors: small/mixed-order A and R combinations (0–4; vector 4 indicates a cofactored
    equation), a pre-reduced scalar (5), S > L (6, 7), non-canonical R (8, 9), non-canonical A (10, 11).
    https://github.com/novifinancial/ed25519-speccheck

## Consequences for the spec

- §2, §8.1: passkey and WebCrypto P-256 signatures are high-S in a large share of cases (findings 2, 8), so root
  verification must use `lowS: false`, and root signatures are malleable; "no identifier, set key or cache key is ever
  derived from a signature" is required, not optional (cf. did:plc, finding 13, which must mandate low-S because it
  hashes signatures).
- §4: record id = SHA-256 of signed bytes excluding the signature is the malleability-safe choice given findings 2 and 8.
- W0–W5 (§6): pin `p256.verify(sig, authData ‖ SHA-256(clientDataJSON), pub65, { format: 'der', lowS: false, prehash: true })`
  with every option passed explicitly, as §2 already does for `zip215: false` (findings 3, 4, 11).
- F2: `p256.verify` can throw (finding 5); the core must map any throw to reject, or pre-validate lengths.
- §2 (canonical bytes): noble's DER decoder accepts one encoding per signature (finding 6), so a strict DER rule costs
  nothing; it is a parser-alignment rule, not a security property, given the high-S malleability.
- §12 differential oracles: SimpleWebAuthn accepts a strict superset of noble on malformed DER (finding 9). The
  differential must assert "noble accepts ⇒ SimpleWebAuthn accepts" and allow divergence only in the direction
  noble-rejects / SimpleWebAuthn-accepts on non-canonical DER, recorded in a committed divergence list. It must not
  assert equality.
- §12 known-answer vectors: Wycheproof P-256 DER must give 484/484 with `lowS: false`; a negative control running
  `lowS: true` must fail exactly 71 (finding 8). The r = s = 0 class (finding 12) is in that file.
- D4: `zip215: false` does not reject mixed-order subject keys (finding 17). D4 needs an explicit torsion-freeness check
  (e.g. noble `isTorsionFree()`) in addition to `isSmallOrder()`, at issue and at verify.
- D4, §12: the 29 Wycheproof "acceptable" Ed25519 vectors (finding 18) and speccheck vectors 0–11 (finding 19) must map to
  **reject**; a harness treating "acceptable" as "either outcome" makes D4 vacuous. The loader asserts counts.
- §12 differential (noble vs WebCrypto Ed25519): run on valid vectors only, because implementations differ on
  small-order checks (finding 16).
- V3: root records use ES256 only, delegate and witness records Ed25519 only; the choice is never read from a key or
  record.
- §5 root: store `pub` as 65-byte `0x04 ‖ x ‖ y` and validate with `Point.fromBytes` (finding 7); reject compressed keys
  so each key has one encoding.

## Unverified

- WebCrypto Ed25519 is enabled by default in Chrome 137+, Firefox 129/130 and Safari 17 (secondary source).
  https://blog.ipfs.tech/2025-08-ed25519/
- noble and WebCrypto agree on P-256 verdicts for valid inputs: tested only indirectly, through SimpleWebAuthn, which
  calls WebCrypto.
- DER strictness of py_webauthn (cryptography), go-webauthn (`crypto/ecdsa.VerifyASN1`, believed to use strict
  `cryptobyte` parsing) and the JCA-based Java libraries: not confirmed.
