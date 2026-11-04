/* eslint-disable */
// Cases for core.yml: each `ruleid:` line must be flagged by that rule, and each `ok:` line must not be.

// ruleid: verify-without-options
ed25519.verify(sig, msg, key)
// ruleid: verify-without-options
libraryVerify(sig, msg, key)
// ok: verify-without-options
libraryVerify(sig, msg, key, OPTIONS)

// ruleid: verify-result-not-strict
if (libraryVerify(sig, msg, key, OPTIONS)) accept()
// ruleid: verify-result-not-strict
if (!p256.verify(sig, msg, key, OPTIONS)) refuse()
// ruleid: verify-result-not-strict
const both = libraryVerify(sig, msg, key, OPTIONS) && other
// ok: verify-result-not-strict
if (libraryVerify(sig, msg, key, OPTIONS) === true) accept()

// ruleid: zip215-enabled
const loose = freeze({ __proto__: null, zip215: true })
// ok: zip215-enabled
const strict = freeze({ __proto__: null, zip215: false })

// ruleid: json-parse-outside-decoder
const parse = JSON.parse
// ruleid: json-parse-outside-decoder
const value = JSON.parse(text)
// ok: json-parse-outside-decoder
const stringify = JSON.stringify

// ruleid: loose-equality
if (a == b) x()
// ruleid: loose-equality
if (a != null) x()
// ok: loose-equality
if (a === b && c !== d) x()

// ruleid: node-only-global
const bytes = Buffer.from(text)
// ruleid: node-only-global
const env = process.env
// ruleid: node-only-global
const fs = require('fs')
// ok: node-only-global
const view = ArrayBuffer.isView(x)
