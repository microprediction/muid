# RFC 8785 reference vectors

- Upstream: https://github.com/cyberphone/json-canonicalization, directory `testdata/`
- Commit: `32a48195b9b20fe67b1795e39e4509f14d860b45`
- Licence: Apache-2.0, copied unchanged as `LICENSE` in this directory.
- Files are byte-for-byte copies of upstream `testdata/input/*.json`, `testdata/output/*.json` and
  `testdata/outhex/*.txt` at that commit. Nothing here is edited.

## SHA-256

```
e503b6d71d1afa595b1c74b1016445c944cd89f90418066b23de1aeda7d17563  input/arrays.json
03676a951cd8753ac62589f72eb2105cc782c33425418cfe1d517c111f6e5d5a  input/french.json
d66893805be1784116af50af3110d08766c70a6b4aad93374723f72346e7aaa6  input/structures.json
4621864e014d4a805a563f55b9ea20aba4a2d2dc09c7394f625496998c00702c  input/unicode.json
c4a041b503d6bc236036ef44db4dac499272f60fc22c40dc3b7a54870ba6f1c3  input/values.json
a3a905266bd4a49a969274ea69baa14ee0c4af0ead926d6fa2b7612b4af75387  input/weird.json
6821faaddedf2d78c95bb6d98b127e9e616097afd2f6bcc34389f000d13ab12d  LICENSE
e306733ca0c4da9595ebde73ec072c295f0f9ef0ea4aafc4d267d4a04988ce51  outhex/arrays.txt
f9b3bfd02f4edb3d0a490703153d836db5ef0a2090a9d3357f8c3797e12d4043  outhex/french.txt
063ee2bc6fa3f93b2a131841315f5c6bf0ea7488cc128ed50725cabf5592627b  outhex/structures.txt
0471fea1ee0464e435a52510d2c187b216961a5e7e2665402ea9cb1cd04109ca  outhex/unicode.txt
b8b802e82c7bead71a7841e27fce6458854eb72ffd0eaa51474dacdfbdf3ab64  outhex/values.txt
1061953c7129537722f9abd9de321c787120489d09f34ba58065bd77ba9a84b6  outhex/weird.txt
099601b171cafed97c333f8878d68e7f8c8f795412adb34b2fdcf0e7c7beac42  output/arrays.json
d99d0ebdcb0033cb858cfa830ae46bc0fb3309413b271f1da828c89901a27ed5  output/french.json
605f65004ec2db7692522a0852c22f1c989e036d547e88963d1a3143cf3195d5  output/structures.json
0d99aad92a125196ff887876643fd3206786a84ddce2cee52ba4ad256d2381d3  output/unicode.json
2d5e01a318d0f0879ab568c4be289c8b1f64ef8921a53c6277d5e069978baacb  output/values.json
6af595a9aa80110b964b4de3f82a05fa6ae7423005019bacfa2620dddc4e94d1  output/weird.json
```

## How the tests use them

None of the six upstream cases lies inside the value domain of SPEC §3: each uses `null`, a float, a key outside
the key grammar, or a top-level array. So they are used in two ways:

1. **Refusal (E3).** Each upstream input, parsed, must be refused by `encode` with the reason code listed in
   `tests/encoding/E3-jcs-refusals.test.mjs`.
2. **Derived string vectors.** Every string value and every string key in the upstream outputs is cut, as raw bytes,
   from the upstream canonical output and wrapped as the value of an in-domain object `{"s": …}`. The expected bytes
   are `{"s":` + the upstream bytes for that string + `}`. The cut is done by a small parser in the test that reads
   only the upstream output, never our encoder, so the expected bytes remain upstream's.
