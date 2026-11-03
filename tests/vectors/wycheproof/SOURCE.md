# Wycheproof test vectors (Ed25519, ECDSA P-256 with SHA-256, DER signatures)

- Upstream: https://github.com/C2SP/wycheproof, directory `testvectors_v1/`
- Commit: `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`
- Licence: Apache-2.0, copied unchanged as `LICENSE` in this directory.
- `ed25519_test.json`: 210 cases (117 valid, 64 invalid, 29 acceptable).
- `ecdsa_secp256r1_sha256_test.json`: 484 cases (174 valid, 310 invalid).
- Byte-for-byte copies at that commit. Nothing here is edited.

## SHA-256

```
182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332  ecdsa_secp256r1_sha256_test.json
ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3  ed25519_test.json
58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd  LICENSE
```
