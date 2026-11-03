# Witness equivocation, backdating and head freshness

## Findings

### Split view and backdating in deployed logs

1. RFC 9162 treats a CT log as a trusted third party; clients SHOULD check consistency with a tree head they already
   hold, and reducing trust in the log is out of scope. https://www.rfc-editor.org/rfc/rfc9162.html
2. Chrome bounds backdating by policy: an SCT counts only if it predates the log's retirement, and at least one SCT
   must come from a log usable at the time of the check. https://googlechrome.github.io/CertificateTransparency/ct_policy.html
3. The Go checksum database client caches the latest signed tree and fails with a security error if a new one does not
   extend it, so a lying server must keep its fork alive for that client indefinitely.
   https://pkg.go.dev/golang.org/x/mod/sumdb , https://research.swtch.com/tlog
4. A C2SP witness cosigns a checkpoint only if it is consistent with the last one it cosigned for that log, checking
   and storing atomically; each cosignature carries the witness's own timestamp. A tlog-proof bundles an entry, its
   inclusion proof and a cosigned checkpoint for offline verification.
   https://c2sp.org/tlog-witness , https://c2sp.org/tlog-cosignature , https://c2sp.org/tlog-proof
5. KERI witnesses keep the first-seen event, watchers detect duplicity, and two inconsistent event logs are proof of
   it; the vLEI framework requires at least five witnesses and three watchers.
   https://gleif.org/vlei/introducing-the-vlei-ecosystem-governance-framework/2025-04-16_vlei-egf-v3.0-technical-requirements-part-1-keri-infrastructure-2024_v1.3_final.pdf
6. Keybase anchored its Merkle root in a public blockchain to detect a forked server. https://book.keybase.io/docs/server/stellar
7. WhatsApp's key directory epochs are cross-signed by an outside party so each is seen once; Apple's contact key
   verification gossips log heads and enforces a 48-hour maximum merge delay; Parakeet requires a threshold of
   witness signatures. https://blog.cloudflare.com/key-transparency ,
   https://security.apple.com/blog/imessage-contact-key-verification/ , https://eprint.iacr.org/2023/081
8. The IETF key transparency architecture states that without a third party, anonymous checks or gossip, a log "can
   show different users different forks without detection", and requires a maximum staleness.
   https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/
9. The did:plc specification says some trust in the PLC server is required; its timestamps are unsigned server
   annotations and it has no witnessing. https://web.plc.directory/spec/v0.1/did-plc

### Revocation lag

10. CA/Browser Forum short-lived certificates need no OCSP or CRL; their maximum lifetime falls to 7 days from
    2026-03-15. https://www.entrust.com/pt/blog/2023/08/short-lived-certificates-finally-approved
11. Let's Encrypt ended OCSP on 2025-08-06 and offers 160-hour certificates without revocation URLs.
    https://letsencrypt.org/2024/12/05/ending-ocsp/ , https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability
12. Firefox CRLite pushes revocation data to clients every 12 hours.
    https://hacks.mozilla.org/2025/08/crlite-fast-private-and-comprehensive-certificate-revocation-checking-in-firefox/

### Several witnesses

13. Signed-note cosignatures are Ed25519 (with a timestamp) or ML-DSA-44; tlog-policy expresses k-of-n quorums with
    nested groups. https://c2sp.org/signed-note , https://c2sp.org/tlog-policy
14. Resisting both split view and denial of service needs k ≥ 1 + ⌊2n/3⌋ cosigners (3-of-4, 4-of-5, 5-of-7); 2-of-3
    does not prevent a split view.
    https://lists.sigsum.org/mailman3/hyperkitty/list/sigsum-general@lists.sigsum.org/thread/ORCPVO33HZM56HZHJ5SO7FIFRAVVTUJY/
15. CVE-2024-54140: a transparency client did not verify a checkpoint's signature.
    https://nvd.nist.gov/vuln/detail/CVE-2024-54140

### Incidents

16. Of 23 CT log failures from 2016 to 2025, four were inconsistent tree heads, all operational: one key shared by a
    test and a production log, a botched restore from backup, and a test log pointed at a production database; one
    log missed its 24-hour merge delay by 2.2 hours. https://transparency.dev/pdfs/summit2025/log_failures.pdf ,
    https://www.agwa.name/blog/post/how_ct_logs_fail

## Consequences for the spec

- R9, F5: a verifier with no memory cannot detect a witness that signs different heads for different relying parties
  (8). A relying party that passes the last head it accepted can (3): with the settled epoch in the head, a newer head
  whose settled epoch is lower, or equal with another settled id, is signed evidence of equivocation. Proposed as
  decision 10.
- R3, R4: a backdated anchor can be bounded only by time from a party other than the witness (2, 4). Starting the
  contest window at the cosigned time of the first checkpoint that includes the anchor would close it; it needs a
  public log with at least one outside cosigner.
- §8 (witness operations, not core): every observed inconsistent head came from operations (16), so the witness
  checks and stores atomically on `(identity, prev)` and on its last head per identity, runs as a single writer, and
  never shares keys between environments.
- R9: a one-day `maxStaleness` is already shorter than the web PKI's status lifetimes (10–12); a relying party that
  needs less lag can poll the witness's log and pass `revoked` and `minHeadAt`.
- R9 (liveness): a witness outage longer than `maxStaleness` refuses every identity; overlapping pinned witness keys
  (A1) and an availability target tied to `maxStaleness` address it, never a grace period.
- not yet in spec: several witnesses need k ≥ 1 + ⌊2n/3⌋ across separate operators (14), with one anchoring witness
  so that one anchor per `prev` (R3) does not become a consensus problem.

## Unverified

- Rekor v2 is said to enable witnessing through tiles and to rely on an RFC 3161 timestamp authority; no description
  of the mechanism was found. https://blog.sigstore.dev/rekor-v2-ga/
- The exact refresh rule for CA/Browser Forum OCSP responses (8 hours to 10 days).
  https://github.com/cabforum/servercert/pull/402
