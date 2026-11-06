# Prior art: the established mechanism behind each rule

The design is meant to combine well-understood mechanisms. This file names the mechanism behind each part of
SPEC.md, how muid differs, and why each difference is kept. Sources were checked on 2026-11-03.

## Findings

### Membership change and recovery (R1–R7)

- **did:plc** (spec v0.3.0, https://web.plc.directory/spec/v0.1/did-plc):
  - Keys: 1–5 rotation keys "in order of descending authority". Each operation has one `sig` and a `prev` CID. There is
    no multisig.
  - Recovery window: `RECOVERY_WINDOW = 72 * HOUR`, measured from the directory's `createdAt` of the first nullified
    operation. Only keys ranked above that operation's signer may rewrite. Source:
    https://github.com/did-method-plc/did-method-plc/blob/main/packages/lib/src/data.ts
  - Time source: `createdAt` is the server's `new Date()` when the operation arrives
    (https://github.com/did-method-plc/did-method-plc/blob/main/packages/server/src/routes.ts).
  - Ordering: writes are serialised `FOR UPDATE`, and a mismatched `prev` gets 409
    (https://github.com/did-method-plc/did-method-plc/blob/main/packages/server/src/db/index.ts).
  - There is no freeze and no cancel. History is final after 72 h, and losing the only key strands the DID.
- **Argent L1**:
  - Recovery needs ceil(n/2) guardians, and the owner is barred from signing. It runs `executeAfter =
    block.timestamp + recoveryPeriod` and locks the wallet.
  - Cancel needs ceil((g+1)/2) of owner and guardians.
  - Anyone can finalize, and any one guardian can `lock` for `lockPeriod`.
  - https://github.com/argentlabs/argent-contracts/blob/develop/contracts/modules/ArgentModule.sol ,
    https://github.com/argentlabs/argent-contracts/blob/develop/contracts/modules/SecurityManager.sol
  - Deployed period values: UNVERIFIED.
- **Safe**:
  - Owner and threshold changes take effect immediately, at the current threshold
    (https://github.com/safe-global/safe-smart-account/blob/main/contracts/base/OwnerManager.sol).
  - Zodiac Delay: anyone may execute after `txCooldown`, measured from `block.timestamp` at queueing. The Safe cancels
    with a forward-only `setTxNonce` (https://github.com/gnosisguild/zodiac-modifier-delay/blob/main/contracts/Delay.sol).
  - RecoveryHub: recoverers "can bypass any threshold". The delay is 28 days by default, and signers at threshold
    reject (https://help.safe.global/articles/9622260218-account-recovery-with-saferecoveryhub).
- **Candide** module 0.2.0:
  - Recovery: a guardian threshold sets `executableAt = block.timestamp + recoveryPeriod`. A rival replaces a pending
    request only with more approvals.
  - Finalize and cancel: anyone may finalize, and the Safe cancels at its owner threshold.
  - Source: https://github.com/candidelabs/candide-contracts/blob/main/contracts/modules/social_recovery/SocialRecoveryModule.sol
  - Default period: 3 days (https://docs.candide.dev/wallet/plugins/recovery-module-reference.md).
- **TUF root rotation**: root N+1 is signed by a threshold of version N's keys *and* a threshold of its own keys, with
  version exactly N+1. The client walks the chain (https://theupdateframework.github.io/specification/latest/).
- **KERI v1.1** (https://trustoverip.github.io/kswg-keri-specification/):
  - A rotation satisfies both the prior next-key threshold (`nt`/`n`) and the new current threshold (`kt`).
  - Witnesses (`b`, `bt`) receipt events.
  - Ordering is "first seen, always seen, never unseen". There is no clock.
  - A compromised pre-rotation cannot be recovered.
  - KAWA formula: UNVERIFIED.

### Witness, freshness and equivocation (R9, F5, decision 10)

- **KEYTRANS:** the architecture draft (-11) is in IESG Evaluation, telechat 2026-12-03
  (https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/); the protocol draft is -06, 2026-11-02, "I-D
  Exists" (https://datatracker.ietf.org/doc/draft-ietf-keytrans-protocol/). A client keeps the last tree size, its
  full-subtree heads and frontier timestamps; sends `last`; accepts a larger head, or the "same" one while within
  `max_ahead`/`max_behind`; and keeps a forked view "forever". Single-party mode needs anonymous or peer-to-peer fork
  checks (https://www.ietf.org/archive/id/draft-ietf-keytrans-protocol-06.txt).
- **C2SP:** a checkpoint is origin, decimal size, base64 RFC 6962 root (https://c2sp.org/tlog-checkpoint). Signed-note
  lines are `— name base64(keyID‖sig)`, keyID = `SHA-256(name‖0x0A‖type‖key)[:4]`, type 0x01 Ed25519, 0x04
  timestamped cosignature; verifiers accept ≥16 signatures and ignore unknown keys (https://c2sp.org/signed-note).
  Cosigners sign `cosignature/v1\ntime <t>\n` plus the checkpoint (https://c2sp.org/tlog-cosignature). A witness takes
  `old <size>` and a consistency proof, answers a stale `old` with 409, and checks-and-persists atomically
  (https://c2sp.org/tlog-witness). Tiles are 256 hashes (https://c2sp.org/tlog-tiles); a tlog-proof is entry,
  inclusion proof and cosigned checkpoint (https://c2sp.org/tlog-proof).
- **RFC 9162:** a tree head is timestamp, size, root; inclusion §2.1.3.2, consistency §2.1.4.2; gossip "not defined
  here" (https://www.rfc-editor.org/rfc/rfc9162.html), its draft "Expired (IESG: Dead)"
  (https://datatracker.ietf.org/doc/draft-ietf-trans-gossip/).
- **Rekor v2:** a "tile-backed transparency log" (https://blog.sigstore.dev/rekor-v2-ga/); clients take the root from a
  verified checkpoint; synchronous witnessing is planned (https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md).
- **TUF:** the timestamp role is "frequently re-signed"; a trusted version "MUST be less than" a new one; every role
  expires (https://theupdateframework.github.io/specification/latest/).
- **did:plc:** directory entries are unsigned (https://web.plc.directory/spec/v0.1/did-plc); tlogs are a "longer goal"
  (https://dholms.leaflet.pub/3m6zswymcqk2p).
- **Go sumdb:** stores the latest signed tree; "SECURITY ERROR" if a new one does not extend it
  (https://github.com/golang/mod/blob/master/sumdb/client.go).

### Delegations and claims (D1–D7, C1)

- **UCAN 1.0:**
  - Envelope: canonical DAG-CBOR with Varsig (https://github.com/ucan-wg/spec/blob/main/README.md).
  - Delegation fields: `iss`, `aud` (the delegatee), `sub`, `cmd`, `pol`, a required `nonce`, `nbf`, and `exp`, which
    must be present but may be null (https://github.com/ucan-wg/delegation/blob/main/README.md).
  - Invocations: a nonce and a short `exp`, with no binding to an HTTP request
    (https://github.com/ucan-wg/invocation/blob/main/README.md).
  - Revocation: the issuer revokes by CID; still at rc.1 (https://github.com/ucan-wg/revocation/blob/main/README.md).
- **Biscuit** (Ed25519 block chain, Datalog checks, https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md)
  and **macaroons** (chained HMACs, https://research.google.com/pubs/archive/41892.pdf) add multi-hop attenuation,
  which D3 forbids.
- **DPoP (RFC 9449, https://www.rfc-editor.org/rfc/rfc9449.html):**
  - Claims: `jti`, `htm`, `htu` "without query and fragment parts", `iat`, `ath`, and `nonce` when the server sent
    `DPoP-Nonce`.
  - Timing: the time must fall in "an acceptable window" (§4.3), on the order of "seconds or minutes".
  - Replay: the server may store `jti` for that window (§11.1).
- **RFC 9421:** covered components include `@method`, `@target-uri` and `@authority`, with parameters `created`,
  `expires`, `nonce` and `keyid`. The body is covered only through a `Content-Digest` that the verifier must check
  (§7.2.8, https://www.rfc-editor.org/rfc/rfc9421.html).

### Provider attestations (A1–A4)

- **Fulcio:**
  - Certificates are "valid for 10 minutes" (https://docs.sigstore.dev/certificate_authority/overview/).
  - Proof of possession is a signature over the token's `sub`. The SAN is set from the subject, and the certificate is
    logged to CT with the SCT embedded (https://github.com/sigstore/fulcio/blob/main/docs/how-certificate-issuing-works.md).
  - The issuer is recorded in OID `1.3.6.1.4.1.57264.1.8` (https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md).
  - Verifiers check the chain, the CT inclusion, and that Rekor's time falls within the certificate's validity. "OIDC
    issuers are highly trusted" (https://docs.sigstore.dev/about/threat-model/).
- **OIDC Core:**
  - §15.5.2: the nonce must "include per-session state and be unguessable". The recommended way is to hash a
    session-bound value.
  - `sub` is "never reassigned" and at most 255 ASCII characters.
  - Source: https://openid.net/specs/openid-connect-core-1_0.html
- **GitHub:** the numeric user ID is "durable", while logins can change (https://docs.github.com/en/rest/users/users).
- **Google:** `sub` is "unique among all Google Accounts and never reused"
  (https://developers.google.com/identity/openid-connect/openid-connect).
- **ORCID:** not re-checked (UNVERIFIED here).

### Encoding (§3)

- RFC 8785's verifier parses, checks and *re-canonicalises* (§5, Appendix F). Appendix C allows the canonical form to
  be the wire format (https://www.rfc-editor.org/rfc/rfc8785.html).
- JWS signs the bytes as sent (RFC 7515 §5.2, https://www.rfc-editor.org/rfc/rfc7515.html).
- COSE wraps headers in a bstr so that no canonical form is needed (https://www.rfc-editor.org/rfc/rfc9052.html).
- muid uses Appendix C plus exact received bytes and E2's round trip: stricter than either. *Adopt as is.*

**Hostile in-process objects.** Mainstream libraries do not defend against them:

- `canonicalize` calls `toJSON` and has no guard against accessors or Proxies
  (https://github.com/erdtman/canonicalize/blob/master/lib/canonicalize.js).
- jose's security policy puts "If an attacker can modify JavaScript prototypes" and "object injection attacks" out of
  scope (https://github.com/panva/jose/blob/main/SECURITY.md).
- The established mechanism is SES `lockdown()`/`harden()`, which still trusts code that ran before lockdown
  (https://github.com/endojs/endo/blob/main/packages/ses/README.md).

§1 already trusts same-origin page code, so E5–E7 defend trusted code against itself; `decode` reads only bytes
(E8). *Adopt jose's stance.* Delete E6, E7 and E5's accessor/Proxy/`Symbol.toStringTag`/internal-slot
checks. Keep E1–E4 and E8. If hostile in-page code ever comes into scope, deploy with SES rather than adding rules to
the core.

## Consequences for the spec

- R1–R6: three established mechanisms combined. Old-and-new threshold rotation (TUF root rotation, KERI); one
  successor per predecessor through a sequencer whose clock is the time source (did:plc's `prev` and serialised
  writes, R3–R4); queue, delay, then finalize or cancel (Zodiac Delay, Candide's recovery module, Argent's recovery
  period, R4–R5). Any one key may lock (Argent, R2).
- R1 deviation: every added root signs, not a threshold of the new set: each new key proves possession (D6's
  reason, and Fulcio's). A strict majority of n roots is ⌊n/2⌋ + 1; Argent's ⌈n/2⌉ is not one for even n.
- R2 deviation: a freeze never expires, since an expiring lock can be waited out by the thief.
- R5 deviation: a contest ends the identity. Established cancels revert, assuming the canceller is not the thief;
  here the thief may hold every root the owner holds, so a reverting cancel allows an endless propose-and-cancel loop.
- R3 deviation: no ranked keys (did:plc's). Any one root may be stolen (§1), so a top-ranked key would be a single
  point of failure.
- R2, open: a pending record's new roots may freeze it; none of the systems above lets an incoming key lock anything.
- R9: the head and `maxStaleness` are TUF's timestamp role and KEYTRANS's `max_behind`, stapled like OCSP.
- Decision 10 has no established counterpart. The established check is a stored checkpoint and a Merkle consistency
  proof (RFC 9162, the Go checksum database, KEYTRANS), with outside cosigners (C2SP tlog-witness).
- D1–D7: a one-hop UCAN in JCS, without nonce or chain, plus D6's proof of possession.
- C1: a DPoP proof with renamed fields, except `request`; DPoP's `htm` and `htu` would replace it.
- A1–A4: Fulcio's pattern (token-bound proof of possession), with a 365-day standing binding instead of ten minutes.
- §3: JCS as the wire format with exact received bytes (RFC 8785 Appendix C). Mainstream libraries do not defend
  serialisation against hostile in-process objects (jose puts prototype tampering out of scope); SES is the
  established mechanism if that ever comes into scope.

## Unverified

- Argent's deployed recovery and lock periods.
- KERI's witness-threshold (KAWA) formula.
- That no npm library implements C2SP signed notes.
