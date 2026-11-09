// decode (SPEC §3): any text is decoded or refused with an EncodingError, never another throw; a text it accepts is
// JSON that encode, given JSON.parse's reading of it, writes back unchanged, so the two parsers agree on it.
import { encoding } from '../../tests/impl.mjs'

const { decode, encode, EncodingError } = encoding

export function fuzz (data) {
  const text = Buffer.from(data).toString('utf8')
  let value
  try {
    value = decode(text)
  } catch (e) {
    if (e instanceof EncodingError) return
    throw e
  }
  if (encode(value) !== text) throw new Error(`decode returned a value that does not encode to its text: ${JSON.stringify(text)}`)
  if (encode(JSON.parse(text)) !== text) throw new Error(`decode and JSON.parse disagree: ${JSON.stringify(text)}`)
}
