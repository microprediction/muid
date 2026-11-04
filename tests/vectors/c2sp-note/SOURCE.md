# Signed notes and checkpoints (C2SP signed-note, tlog-checkpoint, tlog-cosignature)

- `go-note.json`: keys, note text and signatures from golang.org/x/mod `sumdb/note/note_test.go`
  (https://github.com/golang/mod, BSD-3-Clause), the reference implementation of signed notes.
- `tdev-cosignature.json`: verifier keys and a timestamped cosignature from transparency-dev/formats
  `note/note_cosigv1_test.go` (https://github.com/transparency-dev/formats, Apache-2.0).
- `sumdb-checkpoint.txt`: the Go checksum database's checkpoint as served by https://sum.golang.org/latest at
  2026-11-04T04:50:21Z; `sumdb-vkey.txt`: its verifier key, from Go's source (`src/cmd/go/internal/modfetch/key.go`).
- Copied byte for byte; the JSON files hold the upstream strings unchanged.

## SHA-256

```
ee0be445c5c8332b2d3b7387ffc995bf5b177acb76a7e55c4152dc3e4963102d  go-note.json
c00f7436c832432672beb9530e18f32a6b6248a0d7adccf9f7df302e9424e864  sumdb-checkpoint.txt
ee5395896f1d6848b526a3d7e270623b8818ec66579083d5a35187aff14feeb8  sumdb-vkey.txt
bfc5652a09279cc4237b5189fd4f077c610182c252ea3bc98156699a73f6ba59  tdev-cosignature.json
```
