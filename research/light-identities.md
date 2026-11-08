# Proposal: light identities

Status: proposed (SPEC decision 13). Nothing here is in the core yet. Rule labels refer to [`../SPEC.md`](../SPEC.md).

## 1. Intent

muid has two kinds of identity.

- A **heavy identity** is rooted in passkeys (§5 root, identity). It is costly to use on purpose: every signature
  takes a passkey prompt on the id origin, with user verification (W2). It is used rarely: to create the identity, to
  authorise and retire software, and to recover (R1–R10).
- A **light identity** is software acting for a heavy identity: a device, an app, a server, an agent. It holds an
  ordinary Ed25519 key, signs without anyone present, and is limited to the audience, scopes and window its owner
  gave it (D1–D7).

The purpose of the library is that light identities do the work, in a world of services that never need the heavy
identity to be present. A service checks a light identity's claims offline, from signed records and a witness head
(§6), and attributes the work to the heavy identity behind it. Light identities are linkable to the heavy identity
by design (§10, "one identity is correlatable"): a service learns which identity an agent acts for, so the agent's
work counts toward that identity and creating more agents creates no more standing.

What the light keys buy:

1. **Software that acts with nobody present.** A passkey cannot be used by a server, a scheduled job or an agent; a
   light key can.
2. **A small loss when one leaks.** A stolen light key acts for one audience, with its scopes, until its expiry; a
   signature made for one service is refused at another (C1). The root never sits where keys are easy to steal.
3. **Precise, cheap revocation.** Retiring one agent touches nothing else; replacing a root is a succession with a
   contest window.
4. **No prompt per action.** One prompt authorises a key for many signatures.
5. **Attribution to the agent.** Each claim names the key that made it, as well as the identity.

## 2. What is missing

Two gaps keep light identities from standing on their own.

**A light identity is only its key.** A delegation names a `subject` key and has a record id; nothing else names the
delegate. Machine delegations last at most 7 days (decision 3), and a key is replaced whenever a server is. Each
replacement looks to a service like a new agent: its history, its share of the identity's earnings (README goal 6)
and any per-agent limits a service applies start again. The demo shows the identity surviving a worker key's
replacement ("one contributor in History"); it cannot show the *agent* surviving it.

**Renewal needs the heavy identity.** Every delegation is signed by a root (D3), so an agent that runs for months
needs its owner at a browser at least weekly. That is the one place where the heavy identity must still be present.

## 3. Part A: a name for each light identity

- A delegation gains a ninth field, `agent`: a name matching the scope pattern (`^[a-z][a-z0-9_.:-]{0,63}$`).
- The light identity id is hex SHA-256(`UTF-8("muid-agent\n")` ‖ the identity id as 32 raw bytes ‖ `UTF-8(agent)`).
  It is derived, as root and identity ids are, so there is no registry and no record that creates it.
- Every delegation of the same identity with the same `agent` is the same light identity, whatever its key, the root
  that signed it, or the membership it was issued under. Successive delegations are its key history.
- The verifier reports `agent` and the light identity id with the identity, so a service keys per-agent state on the
  light identity id instead of the subject key.
- **Retirement:** a head's `revoked` may name a light identity id, in the same 64-hex form and under the same caps and
  per-root quota as today (R9, R10). It refuses every delegation with that name, past and future: a retired name is
  never reissued, so a later thief holding a root cannot revive an agent's history under it.
- A name is scoped by its identity, so it is unique only within it and asserts nothing outside it.

Established pattern: a workload identity that stays fixed while short-lived keys rotate under it. SPIFFE names a
workload `spiffe://trust-domain/path`, and "all private keys (and corresponding certificates) are short lived,
rotated frequently and automatically" (https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/). An X.509
subject name likewise outlives the key in any one certificate. RFC 8693 separates delegation, where "the actor keeps
its identity", from impersonation (https://www.rfc-editor.org/rfc/rfc8693.html). Here the identity id is the trust
domain, and `agent` the path.

## 4. Part B: renewal without the heavy identity

The pattern is OAuth's refresh token: a long-lived credential whose only power is to obtain short-lived ones, and
which can be revoked centrally (RFC 6749 §1.5, https://www.rfc-editor.org/rfc/rfc6749#section-1.5).

- A **renewal delegation** is a delegation whose scopes are exactly `["muid:renew"]`. It lasts at most 90 days. Its
  `aud` and a new field `grants` (a sorted list of up to 16 scopes) bound what it may hand on. Its key acts at no
  service: a claim under it is refused.
- Its subject key may sign a **task delegation**: the same identity and `agent`; an `aud` equal to the renewal
  delegation's; scopes within its `grants`; a window inside its window; a lifetime of at most one day; and the
  subject's consent as in D6. This is attenuation as UCAN ("equal or narrower capabilities"), ZCAP-LD (a child no
  less restrictive than its parent, and not outliving it) and macaroons require ([delegation.md](delegation.md),
  findings 1 and 4).
- **Depth two by type:** only a root signs a renewal delegation, only a renewal delegation's subject signs a task
  delegation, and a task delegation's subject signs only claims. As in D3, there is no counter to get wrong.
- Both kinds are logged (R10), so the witness knows every key that can verify. Retiring the renewal delegation, its
  key, or the agent's name refuses every task delegation under it.
- The owner then approves an agent's renewal key once per 90 days instead of once a week. The renewal key can be kept
  where keys are hardest to steal (an OS keystore or a hardware token), and the task keys, which work at services,
  live a day.

## 5. Why other designs do not cover this

The scenario: a contributor runs three forecasting agents on two servers for six months. Two services (Forecasts,
which takes submissions, and History, which scores them) must recognise each agent, credit its work to the
contributor, keep each agent's record through key rotation and a lost phone, and stop accepting an agent as soon as
it is retired. The contributor approves things on a phone, rarely.

| Design | What happens in the scenario |
|---|---|
| A key per service (API keys) | Six secrets, one per agent per service. Each service's account is the identity, so History cannot tell that Forecasts' "agent 2" is its own "agent 2" unless the contributor links them by hand. A leaked key has the account's full power at that service until someone notices. |
| Sign in with Google or GitHub (OpenID Connect) | An ID token is issued for a person at a browser, to one client. An agent has no token of its own, so it borrows the person's session. A suspended or lost provider account takes the identity, and every agent's history, with it. |
| OAuth 2.0, refresh tokens, DPoP | The refresh pattern is the one Part B borrows. But the tokens come from one authorization server, for its own resources: unless both trust the same server, Forecasts' tokens mean nothing to History, and the agent is a client registration at one server, not something two services both recognise. |
| Passkeys alone | Every signature needs a person, a prompt and the relying party's own origin. A server cannot hold one without exporting it, which defeats its purpose. muid uses passkeys only for the heavy identity. |
| SPIFFE | The closest design for naming workloads and rotating their keys (Part A follows it). But "an SVID is considered valid if it has been signed by an authority within the SPIFFE ID's trust domain": each contributor would run a signing authority, and each service would federate with each contributor's trust domain. |
| UCAN, Biscuit, ZCAP-LD | Attenuated chains (Part B follows them). Authority traces to the issuer. With a `did:key` issuer that is one key, and replacing it (a lost phone) ends every chain, and the agents' history, under it; continuity needs a DID method that rotates keys, such as did:plc, with its trusted directory. UCAN's revocation is a separate spec, "a last resort". Agents have no names, only keys. |
| Macaroons | Chained HMACs, checked only by holders of the minting service's secret, so History cannot check what Forecasts minted. A macaroon is a bearer token with no audience: whoever copies it can use it. |
| Nostr NIP-26 | The nearest "light key signs for heavy key" design. There is no revocation, so a leaked delegate key stays valid for as long as its conditions allow, and clients show delegated notes as if the delegator published them, so no one can tell which agent did what. It is marked unrecommended. |
| did:plc, KERI | Identifier continuity and recovery, which muid's membership rules follow. In did:plc, signing keys have no control over the DID, and there is no per-audience, per-scope authority for many named agents. |
| RFC 8693 token exchange | Records who acts for whom, but nested `act` claims "are informational only … not to be considered in access control decisions". The tokens are again one authorization server's. |
| Sigstore (Fulcio) | Short-lived certificates bound to a provider identity, logged for lasting attribution, which muid's receipts borrow. They are for signing artefacts, with the provider account as the identity, not for scoped authority at a service. |

Sources: [delegation.md](delegation.md) (UCAN, ZCAP-LD, NIP-26, did:plc, RFC 8693, macaroons, Biscuit),
[oidc-witness.md](oidc-witness.md) (Fulcio, DPoP), [prior-art.md](prior-art.md), and the SPIFFE concepts page above.

The parts muid combines are each established: passkey roots, KERI- and did:plc-style recovery, SPIFFE-style
workload names, refresh-style renewal, UCAN-style attenuation, CT-style logging of every delegation, and DPoP-style
binding of each claim to its request. None of the designs above has all of them, and the scenario needs all of them.

## 6. Costs and open points

- **Core size:** Part A is a field, an id and one more revocation target. Part B adds a second hop to the delegation
  check and the `grants` field. Both are bounded by type, not by counters. The budget (§11) would be raised for it
  deliberately.
- **Lifetimes:** 90 days for renewal and one day for tasks are proposed figures. They replace decision 3's 7 days for
  machines, which stays in force for delegations that are not renewal delegations.
- **Decision 4 (machine autonomy)** is narrowed rather than settled: the owner still chooses the `grants` a renewal
  delegation may hand on.
- **Not proposed:** unlinkable light identities (anonymous credentials, blind signatures, group signatures). They
  would hide which identity an agent acts for, against §10's purpose, and need a much larger cryptographic core.
