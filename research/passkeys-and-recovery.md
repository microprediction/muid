# Passkeys: origins, wallet key hierarchies, sync-provider risk, recovery

## Findings

### Related Origin Requests (ROR)

1. ROR lets a passkey scoped to one RP ID be used from origins listed in `https://<rp_id>/.well-known/webauthn`
   (`application/json`, an `origins` array). Origins already matching the RP ID should not be listed.
   https://passkeys.dev/docs/advanced/related-origins/
2. Clients must support at least 5 unique labels (the name directly before the effective TLD; origins sharing a label
   count once); no known client supports more, so 5 "should be treated as the maximum". The cap exists to "restrict the
   number of unique origins to prevent abuse". ROR "is designed to be used when federation is not possible".
   https://passkeys.dev/docs/advanced/related-origins/
3. Support is detected via `relatedOrigins` in `PublicKeyCredential.getClientCapabilities()`; clients without it need a
   fallback such as a redirect to the RP ID origin. https://passkeys.dev/docs/advanced/related-origins/
4. Support (November 2026): Chrome and Edge 128+ (Android, ChromeOS, macOS, Windows, Ubuntu), Firefox 152+ (Android,
   macOS, Windows, Ubuntu), Safari on macOS 15+, iOS/iPadOS 18+. https://passkeys.dev/device-support/
5. Mozilla lists ROR as shipped in Q2 2026, with UI giving users control over when sites may request passkeys from
   related sites. https://groups.google.com/a/mozilla.org/g/dev-platform/c/60BsGAfXEew
6. Normative text: WebAuthn L3 §5.11 and §5.11.1 "Validating Related Origins".
   https://www.w3.org/TR/webauthn-3/#sctn-related-origins

### Iframes and popups

7. WebAuthn L3 covers embedded use in §5.9 (Permissions Policy), §5.10 (iframes), §5.8.1 (`crossOrigin`,
   `topOrigin`), §13.4.2 (visibility considerations for embedded usage) and §14.5.5 (cross-origin usage).
   https://www.w3.org/TR/webauthn-3/
8. Coinbase Smart Wallet / Base Account uses popups on keys.coinbase.com "so users can see requests and sign with their
   passkey", with cross-domain messaging to the SDK. https://docs.base.org/identity/smart-wallet/features/single-sign-on
9. Porto embeds `id.porto.sh` in an iframe (`frame-src id.porto.sh`, `allow="publickey-credentials-get;
   publickey-credentials-create"`) and uses one popup that creates the passkey account and authorises a session key
   together. https://porto.sh/sdk/faq

### Key hierarchies in passkey-rooted systems

10. Porto key types: `WebAuthnP256` (the passkey) and raw `P256` keys "mainly used for browser session keys"; keys carry
    an expiry and call-level permissions (the SDK example is a one-hour key limited to specific token calls); "super
    admin" keys authorise and revoke other keys. https://porto.sh/sdk/viem/Key ; https://porto.sh/contracts/account
11. Base Spend Permissions: a `SpendPermissionManager` contract lets third-party signers spend within an allowance
    "without any further signatures". Sub Accounts receive spend limits from the parent via `defaultSpendLimits`.
    https://docs.base.org/smart-wallet/guides/spend-permissions ;
    https://docs.base.org/smart-wallet/guides/sub-accounts/sub-accounts-with-privy
12. Privy uses the passkey as an authenticator unlocking key shares, not as the signing root; its FAQ describes a 2-of-2
    split (one share in a TEE), older docs a 3-share Shamir split; the key is reconstituted only in memory during
    signing. https://docs.privy.io/security/security-faqs ; https://docs.privy.io/guide/security/
13. Coinbase Smart Wallet contract reviews (Code4rena, March 2024; Cantina, April 2024) included a cross-chain replay
    issue via `executeWithoutChainIdValidation`. https://code4rena.com/reports/2024-03-coinbase ;
    https://cantina.xyz/portfolio/01f02cc2-24b9-4eee-b6f6-f924d6beee26 ;
    https://github.com/coinbase/smart-wallet/tree/main/audits

### postMessage

14. A `*` targetOrigin leaks tokens; fixes are an exact targetOrigin, checking `event.source` as well as `event.origin`,
    no substring origin checks, and care with the `null` origin of sandboxed frames.
    https://www.microsoft.com/en-us/msrc/blog/2025/08/postmessaged-and-compromised ;
    https://github.com/HackTricks-wiki/hacktricks/blob/master/src/pentesting-web/postmessage-vulnerabilities/README.md

### Sync-provider risk

15. Unit 42, "Pass the Passkey" (3 August 2026), unprivileged malware on Windows with Chrome and Google Password
    Manager: *Pass-ta-key* signs with the device identity key without privilege escalation, unlock or user interaction,
    and succeeds only where RPs do not check the UV flag; *Silver* registers an attacker UV key because the cloud
    authenticator "does not validate the attestation of newly registered UV keys"; *Golden* captures the 32-byte
    security-domain secret from Chrome memory and decrypts all synced passkeys, and "There is no way to rotate or revoke
    the SDS". Synced passkeys show a constant signCount, so clones are not detectable that way. Apple was not assessed.
    https://unit42.paloaltonetworks.com/passwordless-authentication-security-risks/ ;
    https://www.malwarebytes.com/blog/news/2026/08/googles-synchronized-passkeys-can-be-stolen-in-pass-ta-key-attacks

### Recovery

16. FIDO recovery guidance: register multiple authenticators per account to reduce recovery, and recover by re-running
    identity proofing or onboarding.
    https://fidoalliance.org/wp-content/uploads/2019/02/FIDO_Account_Recovery_Best_Practices-1.pdf
17. Synced passkeys survive device loss; device-bound passkeys need a backup authenticator; recovery should be
    risk-based. https://fidoalliance.org/white-paper-fido-authentication-for-moderate-assurance-use-cases/
18. In FIDO UX research, users with passkey-only accounts sought how to access them from devices without the passkey.
    https://fidoalliance.org/wp-content/uploads/2023/05/FIDO-Alliance-UX-Guidelines-for-Passkey-Creation-and-Sign-ins.pdf
19. If every device is lost, synced passkeys are recoverable only through the cloud account plus a device unlock code.
    https://arxiv.org/pdf/2406.18226

## Consequences for the spec

- §8: ROR is capped at 5 labels and edited only by the RP ID owner (findings 1, 2), so it cannot share one root across
  open third-party origins; at most it serves a small first-party family. Whoever can write `/.well-known/webauthn` on
  the id host can authorise new origins to request root assertions, which supports "the id host serves nothing else".
- §8, W0–W5 (§6): if ROR is ever used, `clientDataJSON.origin` is the related origin, not `https://<rp_id>`; the exact
  single-origin rule would become an exact-match allowlist. Not yet in spec.
- §8: clients without ROR or cross-origin `create()` need a top-level id-origin window anyway (findings 3, 4); ROR can
  only be an optimisation over it.
- §8: root-level actions (issuing a delegation, revocation, recovery) happen in a top-level id-origin window,
  whose address bar is the anti-phishing anchor; an iframe can be overlaid by its embedder (§13.4.2, finding 7).
- §5 delegation (`aud`): the id-origin page takes `aud` from the opener's or parent's `event.origin`, never from a
  value the app supplies and never from `topOrigin`.
- I1–I2 (§8): postMessage on the id origin uses an explicit targetOrigin (never `*`), checks
  `event.origin` by exact equality and `event.source`, and rejects the `null` origin (finding 14).
- W0–W5 (§6), F3: UV must be required and checked; Pass-ta-key works exactly where it is not (finding 15).
- not yet in spec (§5 root): record BE/BS at root creation so policy can treat a synced root as relying on the sync
  provider.
- §1: add "compromise of the passkey sync-provider account" to the threat table; it yields valid root
  assertions (finding 15), is not covered by short delegation lifetimes, and is recoverable only by another root.
- R1–R5 (§5): a second passkey in a different sync domain is the FIDO-preferred direction (findings 16, 17) and hedges
  against finding 15; a printed recovery code is a bearer secret whose strength depends on storage and rate limiting.
- R1–R5 (§5): root id depends on `rp_id` and the passkey point, so recovery produces a new root id; carrying
  attestations and reputation over needs a signed root-to-root succession record.
- §5 delegation, §8 and §9 decision 4: Porto's expiring, call-scoped session keys under a passkey admin key (finding 10) are the closest
  analogue to depth-one Ed25519 delegations; unlike Porto and Base, scope is enforced by every relying verifier calling
  `verify`, with no single enforcement point.
- §8 and §9 decision 4: Spend Permissions (finding 11) show that "no further signatures" delegation is where value at risk concentrates.
- U1 (§8): one id-origin popup that creates the root and issues the first delegation (finding 9) halves
  onboarding prompts.
- F4, K3: delegate private keys in app-origin storage are exposed to storage-scraping attacks; short `exp`
  bounds the damage, and non-extractable WebCrypto Ed25519 keys prevent exfiltration (not live misuse).

## Unverified

- Firefox 140 ESR lacks ROR; 153 ESR needed (community forum reply). https://support.mozilla.org/de/questions/1600732
- First-ship versions and dates for ROR in Safari and Firefox beyond passkeys.dev; §5.11.1 details (caching, fetch
  failure, redirects).
- Cross-origin iframe support: `get()` Chrome 84, Firefox 118, Safari 15.5; `create()` Chrome 123, Firefox 123, not
  supported by Safari or any iOS browser as of May 2026; Safari's error "The origin of the document is not the same as
  its ancestors"; Safari does not expose `topOrigin`; Permissions-Policy plus iframe `allow` needed, meta tag not
  reliable, transient user activation needed; Safari third-party cookie blocking breaks iframe state (vendor blogs).
  https://www.corbado.com/blog/iframe-passkeys-webauthn ; https://mojoauth.com/blog/known-broken-passkey-combinations-and-workarounds.md
- Which browsers populate `topOrigin` (Chrome believed to).
- Popup costs (blockers outside a synchronous user gesture, mobile tab switching, `window.opener` lost under COOP): no
  quantified source.
- Base Sub Accounts are owned by the same passkey with their own address.
  https://eco.com/support/en/articles/15254041-coinbase-smart-wallet-deep-dive-2026
- Turnkey runs key generation, signing and policy in AWS Nitro enclaves on QuorumOS with remote attestation.
  https://www.onchainden.com/blog/turnkey-vs-privy
- Web3Auth V1 used Shamir sharing with "shallow MPC" (possibly stale).
  https://blog.particle.network/embedded-web3-wallets-how-to-choose-a-wallet-service/
- keys.coinbase.com uses a single `rp_id` with popup-only access, not ROR.
- About October 2026, a malicious bookmarklet scraped browser storage for Privy- and Turnkey-related session material,
  extracted keys via a hidden iframe, and drained one user of about $48,000 (secondary summary of a SlowMist report).
  https://dev.to/basisdesk/slowmist-uncovers-bookmark-phishing-scheme-draining-embedded-wallets-on-fomo-fdm
- An attacker who enters through a phishable fallback can register a new passkey of any type (Microsoft, Authenticate
  2026, as reported); an Apple ID phishing kit (UNC6671) relays the verification code and asks for the iPhone passcode,
  joining the attacker's device to iCloud Keychain. https://www.corbado.com/blog/passkey-account-recovery-authenticate-2026
- Device-bound passkeys remove the cloud attack surface but move recovery-downgrade risk elsewhere (blog).
  https://brianni.co/blog/synced-passkeys-not-a-security-risk
- Time-locked recovery that any existing root can cancel (the guardian/time-lock pattern of smart-contract wallets).
- Apple iCloud Keychain recovery semantics (escrow, HSM, passcode as factor); Google's response to the Silver attack.
- FIDO "Passkey Index" figures quoted in blogs; passkey recovery success rates; guardian recovery outcomes.
