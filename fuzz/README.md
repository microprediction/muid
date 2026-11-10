# Fuzzing

Coverage-guided fuzzing of the core, nightly (`.github/workflows/fuzz.yml`, SPEC §12; TESTING.md §7). Jazzer.js is
installed here, apart from the repository, with its own lockfile held to the repository's pinning rules.

- `targets/`: one module per target, each exporting `fuzz(data)`; they reach the core through `tests/impl.mjs`.
- `seeds/<target>/`: each target's starting corpus, named by the first 16 hex digits of each file's SHA-256. Every
  seed is run on every pull request by `tests/fuzz/F-seeds.test.mjs`.
  - `decode`: the RFC 8785 reference vectors' `input` and `output` files (byte-for-byte copies of
    `tests/vectors/jcs/`, Apache-2.0, see its `SOURCE.md` and `LICENSE`), and a few short texts.
  - `client-data`: `clientDataJSON` texts as browsers emit them, with and without an extra member, and refused
    variants.
  - `verify`: splices (record, position, deletion, insert) of the valid record set in `targets/verify.mjs`.

To run one target locally: `npm ci --ignore-scripts --prefix fuzz`, then
`fuzz/node_modules/.bin/jazzer fuzz/targets/<target>.mjs <corpus directory> -i "$PWD/src/" --sync`.
