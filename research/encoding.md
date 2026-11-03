# Encoding: canonical forms, signed-token failures, Unicode

## Findings

1. RFC 8785 (JCS) serialises numbers as IEEE-754 doubles printed per ECMAScript, sorts object keys by UTF-16 code
   units, applies no Unicode normalisation, and relies on I-JSON (no duplicate keys) without itself requiring a parser
   that rejects duplicates. A strict parser must be paired with it. https://www.rfc-editor.org/rfc/rfc8785
2. dCBOR (draft-mcnally-deterministic-cbor-18, August 2026, individual draft) applies numeric reduction (−0 becomes 0,
   one NaN) and requires decoders to reject duplicate keys, mis-ordered keys, non-NFC text,
   non-preferred floats and indefinite lengths. https://datatracker.ietf.org/doc/draft-mcnally-deterministic-cbor/
3. Protocol Buffers serialisation is "not (and cannot be) canonical".
   https://protobuf.dev/programming-guides/serialization-not-canonical/
4. Other canonical byte formats in use: canonical S-expressions (https://people.csail.mit.edu/rivest/Sexp.txt),
   bencode (https://www.bittorrent.org/beps/bep_0003.html), SSZ
   (https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md).
5. RFC 8785 reference test data: `testdata/{input,output,outhex}` plus a 100M-line number file
   (`es6testfile100m.txt.gz`) regenerable with `numgen.js` and checkable against published SHA-256 hashes of prefixes.
   The `input/` files include floats and non-ASCII keys. https://github.com/cyberphone/json-canonicalization/tree/master/testdata
6. JWT libraries accepted `alg: none` and confused RS256 with HS256 (public key used as HMAC secret) because the token
   header selected the algorithm. https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/ ;
   RFC 8725 (JWT BCP) https://datatracker.ietf.org/doc/html/rfc8725
7. A survey of 49 JSON parsers found inconsistent duplicate-key handling, enabling parser-differential attacks between
   components that parse the same text.
   https://bishopfox.com/blog/json-interoperability-vulnerabilities
8. ruby-saml CVE-2025-25291 / CVE-2025-25292: two XML parsers in one library disagreed on the same document, enabling
   signature wrapping and sign-in as any user.
   https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/
9. CVE-2022-21449 ("psychic signatures"): Java 15–18 ECDSA accepted r = s = 0 as valid for any message and key.
   https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/
10. EIP-712 prefixes signed structured data with a domain separator so that a signature for one application or type
    cannot be replayed as another. https://eips.ethereum.org/EIPS/eip-712
11. Unicode UTS #39 defines confusable-character detection and skeletons for identifier spoofing.
    https://www.unicode.org/reports/tr39/
12. Property-based testing found serialiser and round-trip bugs of the kinds an injective encoder must exclude:
    javascript-stringify printing `-0` as `"0"`, query-string losing an array element on round-trip, eemeli/yaml
    gaining or losing spaces, jsonwebtoken throwing on keys such as `__proto__` and `valueOf`.
    https://fast-check.dev/docs/introduction/track-record/

## Consequences for the spec

- E2: JCS output alone does not guarantee canonical *input*; the decoder must reject duplicate keys itself (finding 1),
  and the `encode(decode(b)) === b` check is what enforces it.
- E2, §4: parser differentials (findings 7, 8) are avoided only if one parser reads the bytes and the signature is checked
  over exactly the bytes that parser decodes; §4 "never re-serialises in order to verify" is the matching rule.
- E3: dCBOR converts −0 to 0 (finding 2); the spec instead refuses −0 and floats, which keeps E3 "nothing silently
  converted".
- E1: finding 12 lists the near-collision shapes to generate in E1 property tests (`-0` vs `0`, `"1"` vs `1`, prototype
  keys).
- §3: the key regex `^[a-z][a-z0-9_]{0,31}$` excludes `__proto__`, `constructor` and every non-ASCII key, which removes the
  prototype-key and normalisation questions for keys.
- §3: no normalisation is applied to string values, consistent with JCS (finding 1) and unlike dCBOR's NFC requirement
  (finding 2).
- V3: findings 6 and 9 support fixing the algorithm by record type; no header or field may select or weaken it.
- V2, §4, §5: domain-separation prefixes (`muid/v1\n`, `muid-root\n`) play the EIP-712 role (finding 10); the expected
  `type` check prevents cross-type replay.
- §10: commit the cyberphone vectors (finding 5) with an explicit per-file classification: in domain (must match
  `outhex` byte for byte) or out of domain (must throw, E3). Use only the safe-integer lines of the number file.
- §10: a known-answer vector for r = s = 0 (finding 9) belongs in the P-256 set; Wycheproof covers it (see
  [signatures.md](signatures.md)).
- not yet in spec: confusable and normalisation policy for any human-readable name (UTS #39, finding 11) belongs to name
  registration or display, not the codec.

## Unverified

- RFC 8949 §4.2 core deterministic encoding leaves float/integer unification and NaN handling to the application
  (detail not confirmed). https://www.rfc-editor.org/rfc/rfc8949#section-4.2
- PASETO PAE (length-prefixed pieces) is injective over lists of byte strings.
  https://github.com/paseto-standard/paseto-spec/blob/master/docs/Common.md
- ENSIP-15 name normalisation as a model for name registration. https://docs.ens.domains/ensip/15
- `String.prototype.normalize` output depends on the engine's Unicode version, so requiring NFC inside a signing format
  would make verdicts engine-dependent. No primary source cited.
