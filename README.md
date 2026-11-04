# muid

**muid lets a person authorise devices and software agents to act under one continuing identity, each with its own
key and its own limited, expiring permissions, so that any participating service can check — offline, from signed
records — who authorised a piece of software, what it was allowed to do, and which identity its work belongs to.**

Services keep their own access and reputation policies. muid supplies the checkable facts they apply them to.

## The problem it solves

Consider a contributor who runs a forecasting agent on a server. They want:

1. **Limited authority.** The agent can submit forecasts to one service, and nothing else. A stolen agent key cannot
   be used against another service, cannot be used after it expires, and cannot hand its authority on.
2. **Root keys off the worker.** The agent never holds the contributor's passkey. It holds its own key, which the
   passkey authorised.
3. **Continuity.** Replacing the server, rotating the agent's key, or losing a phone does not mean starting over
   under a new name. The identity outlives any one key; with several root passkeys, one stolen key cannot take it
   over, and a change made with it can be contested.
4. **Recognition across services.** A second service — one that displays or scores contributions — recognises the same
   contributor and the same authorised agents, without an account system shared between the two.
5. **Attribution that lasts** (planned). A contribution accepted today remains attributable to the identity after the
   agent's authorisation expires.

## Why existing systems do not do this

Each of these does part of it well, and muid borrows from most of them. None combines the parts.

| System | What it does | What it leaves out, for this purpose |
|---|---|---|
| Sign in with Google, GitHub (OpenID Connect) | Tells one website who a person is, via a provider account | The identity is the provider's account. A software agent gets no key of its own with authority the person limits; each site holds its own session. |
| OAuth 2.0, with DPoP | Grants a client access to one authorization server's resources, with tokens bound to the client's key | Authority is issued and held by that server. A second service does not recognise it, and the person's identity is that server's account. |
| Passkeys (WebAuthn) | Phishing-resistant sign-in, one key per site | No delegation to agents; continuity after losing devices rests on one sync provider's account recovery. muid uses passkeys as its root keys. |
| UCAN, Biscuit, macaroons | Delegable capability tokens | No identity continuity or recovery of their own: a token's authority traces to its issuer's key. Their chains and policy languages are more than this needs; muid allows one hop, an exact audience and flat scopes. |
| did:plc, KERI | An identifier whose keys can rotate and be recovered | No audience-bound delegation to agents, and no request-bound proof of action. muid's recovery rules follow theirs. |
| Sigstore | Short-lived signing certificates bound to a provider identity, logged for later verification | Built for signing software artefacts, with the provider account as the identity. muid borrows its pattern for lasting attribution. |

What muid adds is the combination, in one small signed-record format with one synchronous verifier: a continuing
identity with contestable recovery, delegations to agents bound to an audience, scopes and a time window, claims bound
to a single request, and revocation — checked by any service against a fresh signed summary of the identity's keys.

## What it is not

- **Not proof of a unique human.** Anyone can create an identity. Sybil resistance and reputation are left to the
  services that use muid, which may weigh the same records differently.
- **Not trustless.** It depends on a witness service that orders key changes and signs, at least daily, a summary of
  each identity's keys and revocations, and on a dedicated web origin that holds the passkeys' relying-party ID.
- **Not a replacement for logging in to one website.** For a single site, OpenID Connect or passkeys are enough.
- **Not endorsement.** A delegation grants authority to act. Work done under it is attributable to the identity, but
  is not a statement that its owner reviewed or endorses it.
- **Not private across services.** Every service sees the same identity id. For a public contributor history that is
  the point; separate activities call for separate identities.

## Status

The v1 core in [`src/`](src/) is written and tested: canonical records, Ed25519 and passkey (P-256) signatures,
roots, delegations, provider attestations, membership changes with recovery, and the verifier relying parties call.
Not yet built: the witness service, the identity page, client packages, and lasting attribution receipts.

- [`SPEC.md`](SPEC.md): threat model, record formats and every rule the verifier applies.
- [`TESTING.md`](TESTING.md): how each rule is tested.
- [`research/`](research/README.md): sources behind the rules, including the established mechanism each follows.
- [`model/`](model/): executable models of membership and recovery that the implementation is checked against.

The previous Python package is in [`muid-archive/`](muid-archive/).
