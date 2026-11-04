# Research

Background research behind the draft spec in [`../SPEC.md`](../SPEC.md). Sources were checked as of November 2026.

| File | Topic |
|---|---|
| [encoding.md](encoding.md) | Canonical encodings (JCS, dCBOR, others), signed-token and parser-differential failures, Unicode handling |
| [signatures.md](signatures.md) | ECDSA P-256 in WebCrypto and noble (low-S, DER, prehash), Ed25519 verification rules and noble options |
| [webauthn.md](webauthn.md) | WebAuthn L3 §7.2 assertion checks, server-library behaviour, published advisories, COSE keys, test plan |
| [passkeys-and-recovery.md](passkeys-and-recovery.md) | Related Origin Requests, iframes vs popups, passkey-rooted wallet designs, sync-provider risk, recovery |
| [delegation.md](delegation.md) | UCAN, ZCAP, Biscuit, did:plc, KERI, NIP-26, RFC 8693, X.509: scope, audience, depth, time, revocation |
| [oidc-witness.md](oidc-witness.md) | Binding provider accounts to keys (Fulcio, DPoP, PKCE, nonce), GitHub/Google/ORCID identifiers, device flow |
| [witness.md](witness.md) | Witness equivocation and backdating in CT, checksum databases, KERI, key transparency, did:plc; revocation lag; several witnesses |
| [prior-art.md](prior-art.md) | The established mechanism behind each rule (TUF, KERI, did:plc, Delay/Candide/Argent, KEYTRANS, C2SP, UCAN, DPoP, Fulcio), and each deviation kept |
| [assurance.md](assurance.md) | Mutation testing, property testing, fuzzing, linters, known-answer vectors, supply chain, anti-vacuity |

## Structure of each topic file

- `## Findings`: numbered. Each carries its source URL(s) inline.
- `## Consequences for the spec`: each line starts with the SPEC.md rule label (E1–E8, V1–V5, K1–K7, D1–D7, A1–A4, O1, R1–R9, F1–F4, W0–W6, I1–I5, U1–U3) or
  section (§N, §N.M) it informs, or "not yet in spec".
- `## Unverified`: claims that lack a primary source. Secondary or informal sources are given where one exists. Treat
  these as leads, not citations.

## Verification marks

- **URL inline** — the finding is stated by the linked primary source (standard, RFC, vendor documentation, advisory,
  project source or the original research publication).
- **Measured locally (tool, version)** — the result comes from running code or reading a pinned package's source
  directly. The tool and exact version are named; the package or repository URL is given as the source. Re-running
  against a different version may give a different result.
- **(source read)** — a "Measured locally" finding obtained by reading the named file of the named package version,
  not by executing it.
- **Unverified section** — not confirmed against a primary source; the stated source, if any, is secondary.
