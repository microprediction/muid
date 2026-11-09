# muid

**muid lets a person authorise devices and software agents to act under one continuing identity, each with its own
key and its own limited, expiring permissions, so that any participating service can check — offline, from signed
records — who authorised a piece of software, what it was allowed to do, and which identity its work belongs to.**

Services keep their own access and reputation policies. muid supplies the checkable facts they apply them to.

## Heavy and light identities

An identity is **heavy**: rooted in passkeys, and used rarely, to create it, to authorise and retire software, and to
recover it. The work is done by **light** identities: devices, apps, servers and agents, each holding its own
Ed25519 key, acting with nobody present, and limited to what the owner granted. Services deal only with light
identities and check them offline. They never need the heavy identity to be present, yet the work of every light
identity is attributed to the heavy identity behind it, which every service can see.

What the light keys buy:

- **Software can act.** A server, a scheduled job or an agent cannot use a passkey; it can use a light key.
- **A leak costs little.** A stolen light key works at one service, with its scopes, until it expires. The passkey
  never sits where keys are easy to steal.
- **Retiring one agent touches nothing else.** Replacing a passkey is a contested succession; replacing a light key
  is routine.
- **No prompt per action.** One passkey prompt authorises a key for many signatures.
- **Each action names the key that made it**, as well as the identity.

Each delegation names its agent, so a light identity keeps its name, and its history at a service, when its key is
replaced; retiring the name retires the agent for good. Renewing one still needs the passkey weekly:
[`research/light-identities.md`](research/light-identities.md) proposes renewal without it (SPEC decision 13), and
works one scenario through each of the designs below.

## The problem it solves

The organizing example: **log in, authorise a temporary agent, let it contribute, retire it, and collect its later
earnings under the continuing identity.** An agent might exist for an hour, submit forecasts, and stop; its
credentials expire, but its submissions, and the right to whatever they earn once scored, stay with the identity
that created it. The contributor wants:

1. **Limited authority.** The agent can submit forecasts to one service, and nothing else. A stolen agent key cannot
   be used against another service, cannot be used after it expires, and cannot hand its authority on.
2. **Root keys off the worker.** The agent never holds the contributor's passkey. It holds its own key, which the
   passkey authorised.
3. **Continuity.** Replacing the server, rotating the agent's key, or losing a phone does not mean starting over
   under a new name. The identity outlives any one key; with several root passkeys, one stolen key cannot take it
   over, and a change made with it can be contested.
4. **Recognition across services.** A second service — one that displays or scores contributions — recognises the same
   contributor and the same authorised agents, without an account system shared between the two.
5. **Attribution that lasts.** A contribution accepted today remains attributable to the identity after the agent's
   authorisation expires: the service bound the beneficiary when it accepted the contribution, and logged a receipt.
6. **Earnings that outlast the agent.** Scored later, a contribution's earnings are credited to the identity, with
   each agent's share shown; the owner collects them from any device of the identity, and the retired agent cannot.
   No transfer is needed.
7. **More agents, no more standing.** Every agent's work resolves to the one identity that authorised it, so
   creating a hundred agents earns more only by doing more useful work; it creates no new identities, votes or
   allowances. Deciding who gets an identity in the first place — admission, Sybil resistance — is the next layer's
   policy, applied to these facts.

## Why existing systems do not do this

Each of these does part of it well, and muid borrows from most of them. None combines the parts.

| System | What it does | What it leaves out, for this purpose |
|---|---|---|
| Sign in with Google, GitHub (OpenID Connect) | Tells one website who a person is, via a provider account | The identity is the provider's account. A software agent gets no key of its own with authority the person limits; each site holds its own session. |
| OAuth 2.0, with DPoP | Grants a client access to one authorization server's resources, with tokens bound to the client's key | Authority is issued and held by that server. A second service does not recognise it, and the person's identity is that server's account. |
| Passkeys (WebAuthn) | Phishing-resistant sign-in, one key per site | No delegation to agents; continuity after losing devices rests on one sync provider's account recovery. muid uses passkeys as its root keys. |
| UCAN, Biscuit, macaroons | Delegable capability tokens | No identity continuity or recovery of their own: a token's authority traces to its issuer's key. Their chains and policy languages are more than this needs; muid allows one hop, an exact audience and flat scopes. |
| did:plc, KERI | An identifier whose keys can rotate and be recovered | No audience-bound delegation to agents, and no request-bound proof of action. muid's recovery rules follow theirs. |
| A key per service (API keys) | Lets software call one service | Each service's account is the identity. Nothing ties one service's key for an agent to another's, and a leaked key has the account's full power there. |
| SPIFFE | Stable workload names over short-lived, rotated keys | Every credential is signed by an authority the trust domain runs, and services federate with each domain: built for an organisation's workloads, not a person's agents. muid's proposed agent names follow it. |
| Nostr NIP-26 | One key signs on behalf of another | No revocation, and delegated notes are shown as the delegator's, so agents cannot be told apart. Marked unrecommended. |
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
roots, delegations, provider attestations, membership changes with recovery, transparency-log proofs and receipts,
and the verifier relying parties call. Around it: the relying-party adapter ([`adapter/`](adapter/)), the witness
and its service ([`witness/`](witness/)), the transparency log (Tessera, [`log/`](log/)), the identity page
([`id/`](id/)), and a two-application demo ([`demo/`](demo/)) that runs the example above end to end. Not yet:
client packages, and a deployment.

- [`SPEC.md`](SPEC.md): threat model, record formats and every rule the verifier applies.
- [`TESTING.md`](TESTING.md): how each rule is tested.
- [`research/`](research/README.md): sources behind the rules, including the established mechanism each follows.
- [`model/`](model/): executable models of membership and recovery that the implementation is checked against.

The previous Python package is in [`muid-archive/`](muid-archive/).
