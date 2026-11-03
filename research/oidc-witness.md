# OAuth/OIDC witness and device-flow onboarding

## Findings

### Sigstore Fulcio

1. Fulcio issues X.509 certificates "valid for 10 minutes" for an OIDC identity, logged in a certificate transparency
   log. https://docs.sigstore.dev/certificate_authority/overview/
2. Fulcio's proof of possession is a signature over the token's `sub` (or a CSR); the certificate SAN is set to the
   token subject and the issuer goes into an extension.
   https://github.com/sigstore/fulcio/blob/main/docs/how-certificate-issuing-works.md
3. Recent Fulcio advisories are SSRF or DoS in issuer/JWKS handling: GHSA-55r8-p8r6-2f8m (blind SSRF via JWKS lookup for
   meta issuers, 2026-10-05); GHSA-f5mr-q85p-6hh6 (following OIDC discovery redirects allows SSRF and **JWKS
   substitution**, 2026-05-26); GHSA-59jp-pj84-45mr / CVE-2026-22772 (SSRF via MetaIssuer regex bypass, 2026-01-12);
   GHSA-f83f-xpx7-ffpw (memory exhaustion in token parsing, 2025-12-04).
   https://github.com/sigstore/fulcio/security/advisories . The GHSA-59jp fix needs Fulcio ≥ 1.8.5 and the GHSA-f83f fix
   ≥ 1.8.3; both upgrades broke dependent builds. https://images.chainguard.dev/security/CGA-2235-rrqx-935p ;
   https://images.chainguard.dev/security/CGA-5p76-wm5c-xxjq

### Binding a sign-in to a key

4. DPoP (RFC 9449) binds access tokens to a client key via `cnf.jkt`; `dpop_jkt` binds the authorization code, and the
   server "MUST reject" a mismatch, with protection only "when a unique DPoP key is used for each authorization
   request"; a compromised client can pre-generate proofs unless the server issues nonces.
   https://www.rfc-editor.org/rfc/rfc9449.html
5. RFC 9700: public clients MUST use PKCE, S256 is the only method that does not expose the verifier; without PKCE or
   nonce, one-time CSRF tokens go in `state`; a client using nonce "MUST validate the `nonce` in the ID Token", and nonce
   "does not protect authorization codes of public clients"; clients of several authorization servers "MUST prevent
   mix-up attacks" with RFC 9207 `iss` or a distinct redirect URI per issuer; authorization servers "MUST utilize exact
   string matching" for redirect URIs; clients SHOULD NOT use the implicit grant.
   https://www.rfc-editor.org/rfc/rfc9700.html
6. Google: `state` about 30 characters from a high-quality RNG, and the app "must confirm that the `state` received from
   Google matches the session token"; `nonce` "enables replay protection".
   https://developers.google.com/identity/openid-connect/openid-connect

### Provider identifiers

7. GitHub: "After changing your username, your old username becomes available for anyone else to claim"; repository
   redirects stop working once the old name is reused.
   https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-personal-account-settings/changing-your-github-username
8. A third-party service keyed accounts on GitHub username and allowed account theft through username change.
   https://gitlab.com/code-stats/code-stats/issues/55
9. Google: `sub` is "unique among all Google Accounts and never reused", "never changed", at most 255 case-sensitive
   ASCII characters; `email` "could change over time" and "you shouldn't use this value as the primary identifier";
   `hd` must be checked when restricting access, and the `hd` request parameter is only a UI hint; `iss` is "Always
   `https://accounts.google.com` or `accounts.google.com`"; `aud` must equal the client id.
   https://developers.google.com/identity/openid-connect/openid-connect
10. Truffle Security (January 2025): buying a defunct startup's domain lets an attacker recreate Workspace accounts and
    sign in with Google to that startup's former SaaS tools; over 100,000 such domains for sale; `sub` reported to change
    in about 0.04% of logins (from one downstream engineer), which is why services fall back to email and `hd`; Google
    initially closed it as "Won't fix". https://trufflesecurity.com/blog/millions-at-risk-due-to-google-s-oauth-flaw
11. ORCID production discovery: issuer `https://orcid.org`, JWKS `https://orcid.org/oauth/jwks`, `scopes_supported:
    ["openid"]`, `response_types_supported` includes implicit `id_token`, RS256 only, `subject_types_supported:
    ["public"]`. https://orcid.org/.well-known/openid-configuration . With `openid`, an id_token is returned in the token
    response. https://info.orcid.org/faq/what-is-openid . A separate sandbox (sandbox.orcid.org) exists.
    https://github.com/ORCID/orcid-auth-widget

### Incidents

12. nOAuth (2023): in Azure AD the `email` claim "is both mutable and unverified so it should never be trusted"; apps
    merging accounts by email were taken over; Microsoft added `xms_edov` and `RemoveUnverifiedEmailClaim`; `sub`
    recommended. https://www.descope.com/blog/post/noauth
13. Mix-up attacks and redirect-URI substitution are covered by RFC 9700 §4.4.2 and §4.1.3.
    https://www.rfc-editor.org/rfc/rfc9700.html

### Device authorization grant (RFC 8628)

14. RFC 8628 §5: rate-limit user-code attempts (an 8-character base-20 code ≈ 34.5 bits needs limits of about 5
    attempts); device codes SHOULD have very high entropy; tell the user they are authorising a device and display
    device information (§5.4); an observer can hijack by "completing the authorization faster" (§5.5); devices are
    public clients (§5.6); clients "MUST still display the user_code" (§3.3.1). https://www.rfc-editor.org/rfc/rfc8628.html
15. Storm-2372 (Microsoft, 2025-02-13): device-code phishing since August 2024 via fake meeting invites; from
    2025-02-14 used the Microsoft Authentication Broker client id to register devices and obtain PRTs. Mitigations:
    block device code flow where possible, revoke refresh tokens, require phishing-resistant MFA, which does not by
    itself stop consent phishing because the victim authenticates genuinely.
    https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
16. RFC 10027 / BCP 247, Cross-Device Flows (August 2026): consent and session phishing are "effective even when
    multi-factor authentication is deployed"; "The only mitigation against this unauthenticated channel is the user's
    judgment"; FIDO/WebAuthn cross-device flows using BLE proximity "are the RECOMMENDED approach"; "Implementers SHOULD
    avoid cross-device flows if risks cannot be sufficiently mitigated".
    https://datatracker.ietf.org/doc/draft-ietf-oauth-cross-device-security/

## Consequences for the spec

- A2: Fulcio's proof of possession (finding 2) is identical for every sign-in by the same identity; A2's signature over
  the per-session `state` is session-bound. Stronger still: sign a witness-chosen, domain-separated message such as
  `"muid-attest-v1\n" ‖ witness_id ‖ provider ‖ state ‖ root ‖ exp`. The exact message is not yet in spec.
- A2, not yet in spec: for OIDC providers (Google, ORCID), set `nonce` = hex(SHA-256(that signed message)) so the
  provider-signed id_token commits to the proof of possession (findings 5, 6). GitHub has no id_token, so binding there
  rests on `state` and the witness's own API call.
- not yet in spec (witness protocol): code flow with PKCE S256 only, never implicit (findings 5, 11); `state` ≥ 128 bits,
  single use, server-side; mix-up defence by stored issuer compared with `iss` (Google, ORCID) and a distinct redirect
  URI per provider (GitHub); exact registered redirect URIs and no open redirects on the witness origin;
  `response_mode=query` with a server-side callback.
- A1, §1: support a closed set of hard-coded issuers with pinned JWKS URLs (or the GitHub API host); no discovery
  redirects, wildcard or meta issuers (finding 3).
- §5 attestation (`account`): GitHub = decimal numeric `id` from `GET https://api.github.com/user` with the token just
  obtained, never `login` (findings 7, 8); Google = `sub` verbatim, never `email` or `hd` (findings 9, 10, 12); ORCID =
  bare iD from `sub`, format-checked, never the URI form. No account merging by email.
- §5 attestation (`provider`): a closed enum mapped one-to-one to a pinned issuer; Google's two `iss` spellings map to
  one provider value (finding 9); ORCID sandbox issuer rejected outside tests (finding 11).
- §8.4: short attestation lifetimes let deleted or reassigned accounts age out and limit provider-side mis-issuance;
  a Google `sub` change (finding 10) fails closed by requiring re-attestation.
- not yet in spec: publishing attestations to an append-only log lets account owners detect mis-issuance (Fulcio
  model, finding 1).
- §1: a provider minting a token for the wrong user is out of scope as "a compromised provider"; short lifetimes and a log
  bound the damage.
- §8.5, D3: device-flow onboarding (findings 14–16): the machine generates its Ed25519 key first and the request carries
  it as `subject`; the id-origin approval page shows the key fingerprint (also shown on the machine) and the requested
  `aud`, `scopes` and `exp`; approval yields a delegation signed by the root passkey, never a bearer token; user codes
  short-lived (≤ 10 min), single use, ≥ 8 base-20 characters, rate-limited; every device-flow delegation logged or
  notified.
- A2, §8.5: the `attest` scope and any root-equivalent scope are never granted through device flow.
- §8.5: preferred order of machine enrolment: same-device WebAuthn; FIDO hybrid with BLE proximity (finding 16);
  user-initiated out-of-band enrolment (the user enters the machine's public key on the id origin and the machine polls),
  which reverses the direction a phisher needs; QR transport only with fingerprint binding.

## Unverified

- Fulcio's token audience is `sigstore`; public Sigstore uses a Dex federation instance (oauth2.sigstore.dev) to turn
  GitHub OAuth into OIDC; Fulcio advisories before 2025 on issuer/claim confusion.
- GitHub, Google and ORCID support for DPoP `dpop_jkt` (believed absent) and for the RFC 9207 `iss` response parameter.
- GitHub issues no OIDC id_token for user sign-in (its OIDC issuer covers Actions workload tokens only); GitHub numeric
  user ids are never reused.
- A deleted GitHub account name was re-registered and used to republish a forked tool (2018, press).
  https://www.theregister.com/2018/02/10/github_account_name_reuse/
- Google later reopened the defunct-domain report with a bounty; changes to `email_verified` for non-Gmail accounts.
  Secondary coverage: https://www.securityweek.com/google-oauth-flaw-leads-to-account-takeover-when-domain-ownership-changes/ ;
  https://thehackernews.com/2025/01/google-oauth-vulnerability-exposes.html
- ORCID iD format: 16 characters with hyphens, `^\d{4}-\d{4}-\d{4}-\d{3}[\dX]$`, ISO 7064 MOD 11-2 check character;
  sandbox issuer `https://sandbox.orcid.org`; ORCID id_token lifetime and nonce handling.
- Sign in with Apple (April 2020): Apple's servers issued a valid JWT for any requested Apple ID email (press).
  https://thehackernews.com/2020/05/sign-in-with-apple-hacking.html
- OAuth code and token leakage through `response_mode`/postMessage gadgets ("Dirty Dancing", 2022); nOAuth still
  affecting Entra multi-tenant apps in 2025.
- A "37x surge" in device-code phishing account takeovers (headline only).
  https://labs.cloudsecurityalliance.org/research/csa-research-note-oauth-device-code-phishing-surge-20260405/
- RFC 10027 number and date (confirm on rfc-editor.org); its sections beyond proximity; CIBA and FIDO hybrid transport
  details; Volexity and Proofpoint device-code reports.
