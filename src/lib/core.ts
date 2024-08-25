import * as cbor from 'cbor'
import msgpack5 from 'msgpack5'
import { encodeBase64Url } from './base64.js'
import { Sizes } from './code-tables.js'
import { Dict } from './data-structures.js'
import { DigestAlgoMap, SAIDDex } from './digests.js'
import { fromBytes, toBytes } from './encoding.js'
import { deversify, versify, Version } from './versions.js'

/**
 * Serialization types for the version field 'v'
 */
export enum Serials {
  JSON = `JSON`,
  CBOR = `CBOR`,
  MGPK = `MGPK`,
}

/**
 * Protocol types for the version field 'v'
 */
export enum Protocols {
  KERI = `KERI`,
  ACDC = `ACDC`,
}

/**
 * Utility function to handle serialization by kind
 * @param data - data to serialize to bytes
 * @param kind - type of serialization to create
 * returns raw bytes of the serialized version of the data Object
 */
export function dumpBytes(data: Object, kind: Serials): Uint8Array {
  switch (kind) {
    case Serials.JSON:
      return toBytes(JSON.stringify(data))
    case Serials.CBOR:
      return cbor.encode(data)
    case Serials.MGPK:
      const encoder = msgpack5()
      return encoder.encode(data).slice()
    default:
      throw new Error('unsupported event encoding')
  }
}

/**
 * Compute serialized size of a data object and update the version field.
 * Returns a tuple of associated values extracted or changed by sizeify
 * @param data - data object to add a size attribute to and serialize
 * @param kind - type of serialization to make
 */
export function sizeify(
  data: Dict<any>,
  kind?: Serials,
): [Uint8Array, Protocols, Serials, Dict<any>, Version] {
  if (!('v' in data)) {
    throw new Error('Missing version field "v" in data object')
  }

  const [protocol, version, knd] = deversify(data['v'] as string) // size ignored since adding size below
  if (kind == undefined) {
    kind = knd
  }

  // calculate size of serialized data
  let raw = dumpBytes(data, kind ? kind : knd)
  const size = raw.length

  data['v'] = versify(protocol, version, kind, size)

  // re-serialize with updated version field
  raw = dumpBytes(data, kind)

  return [raw, protocol, kind, data, version]
}

/**
 * Character used to pad SAID values prior to calculation of the digest.
 */
export const SAID_PAD_CHARACTER = `#`

/**
 * Serialize data with serialization kind if provided otherwise inspect 'v' version string for kind
 * @param data - data to serialize
 * @param kind - serialization kind, defaults to JSON
 */
export function serialize(data: Dict<any>, kind?: Serials): Uint8Array {
  let knd = Serials.JSON
  if ('v' in data) {
    ;[, , knd] = deversify(data['v'])
  }
  if (kind == undefined) {
    kind = knd
  }
  return dumpBytes(data, kind)
}

/**
 * Derives the raw SAID bytes from arbitrary data passed in as a field map object (Dict).
 * Defaults to using the customary letter `d` as the label. The 'd' stands for digest.
 *
 * @example
 *
 * ```ts
 *   const myData = {
 *     a: 1,
 *     b: 2,
 *     d: ''
 *   }
 *   const label = 'd';
 *   const said = deriveSAIDBytes(myData, label);
 *   // you can now use this SAID Uint8Array to create a fully qualified Base64 SAID
 * ```
 *
 * @param data - data to derive self-addressing data from and to add to as a prop labeled by `label`
 * @param code - algorithm to be used to derive the SAID
 * @param kind - type of serialization to use
 * @param label - name of the property in the "data" field that will have the SAID placed inside
 */
export function deriveSAIDBytes(
  data: Dict<any>,
  code: string = SAIDDex.Blake3_256,
  kind: Serials = Serials.JSON,
  label: string = `d`,
): [Uint8Array, Dict<any>] {
  if (!(label in data)) {
    throw new Error(`Missing id field labeled "${label}" in `)
  }
  data = { ...data }
  const algo = Sizes.get(code)
  if (algo === undefined) {
    throw new Error(`Unsupported digest algorithm code = ${code}`)
  }
  data[label] = ''.padStart(algo.fs, SAID_PAD_CHARACTER)
  if (`v` in data) {
    ;[, , kind, data] = sizeify(data, kind)
  }

  const digestage = DigestAlgoMap.get(code)
  if (!digestage) {
    throw new Error(`Unsupported digest algorithm code = ${code}`)
  }

  const ser = serialize({ ...data }, kind)

  const raw = digestage.fn(ser)
  validateRawSize(raw, code)

  return [raw, data]
}

/**
 * Create a fully qualified Base64 representation of the raw bytes encoded as bytes.
 * This implementation only uses the hard part of the code as SAIDs do not have a variable part (soft size).
 *
 * Analogous to the Matter._infil() function from KERIpy
 *
 * @param raw - the raw bytes to encode
 * @param code - the algorithm derivation code to use
 */
export function qb64b(raw: Uint8Array, code: string = SAIDDex.Blake3_256): Uint8Array {
  const sizeage = Sizes.get(code)
  if (sizeage === undefined) {
    throw new Error(`Unsupported digest algorithm code = ${code}`)
  }
  const [hs, ss, _fs, ls] = [sizeage.hs, sizeage.ss, sizeage.fs, sizeage.ls]
  const cs = hs + ss
  const rs = raw.length
  const ps = (3 - ((rs + ls) % 3)) % 3 // net pad size given raw size and lead size
  // net pad size must equal both code size remainder so that primitive both + converted padded raw is fs long.
  // Assumes ls in (0, 1, 2) and cs % 4 != 3, fs % 4 == 0. Sizes table must ensure these properties.
  // Even still, following check is a good idea.
  if (cs % 4 !== ps - sizeage.ls) {
    throw new Error(`Invalid code size for ${code} and raw pad size ${ps} given raw length ${rs}`)
  }

  // Prepad raw so we midpad the full primitive. Prepadding with ps+ls zero bytes ensures encodeB64 of
  // prepad+lead+raw has no trailing pad characters. Finally skip first ps == cs % 4 of the converted characters
  // to ensure that when full code is prepended the full primitive size is fs but midpad bits are zeros.
  const prepad = new Uint8Array(ps + ls)
  const combined = new Uint8Array(prepad.length + raw.length)

  // fill out prepad
  // when fixed and ls != 0 then cs % 4 is zero and ps === ls
  // otherwise fixed and ls === 0 then cs % 4 === ps
  for (let i = 0; i < ps; i++) {
    prepad[i] = 0
  }
  combined.set(prepad)
  // adjust the bytes considering padding
  combined.set(raw, prepad.length)

  return toBytes(code + encodeBase64Url(Buffer.from(combined)).slice(ps))
}

/**
 * Create a fully qualified Base64 representation of the raw bytes encoded as a UTF-8 string.
 * @param raw - the raw bytes to encode
 * @param code - the algorithm derivation code to use
 */
export function qb64(raw: Uint8Array, code: string = SAIDDex.Blake3_256): string {
  return fromBytes(qb64b(raw, code))
}

/**
 * Calculates the raw size in bytes not including the leader (leading pad bytes) for a given code.
 * Converts the Base64-encoded size back to the original byte size.
 *
 * @param code - the algorithm derivation code to calculate the raw size for
 */
export function rawSize(code: string = SAIDDex.Blake3_256): number {
  if (code.length === 0) {
    throw new Error('Invalid code, cannot calculate size.')
  }
  const sizeage = Sizes.get(code)

  if (sizeage === undefined) {
    throw new Error(`Unsupported digest algorithm code = ${code}`)
  }
  if (sizeage.fs === -1) {
    throw new Error(`Unsupported variable size code=${code}`)
  }

  const cs = sizeage.hs + sizeage.ss // code size
  const b64Size = sizeage.fs - cs // Strip the code size from the full size to get the Base64 size

  // converts a Base64-encoded size back to the original byte size
  // each Base64 character is 6 bits so the original size can be found by multiplying the
  // Base64 length by 6/8 or the equivalent fraction, 3/4, as below
  // rize = raw size in bytes
  return Math.floor(b64Size * (3 / 4))
    - sizeage.ls // subtracting the lead pad bytes size (ls)
}

/**
 * Check whether the raw bytes contain enough content for the given derivation code algorithm.
 * @param raw - raw bytes to check
 * @param code - derivation code algorithm to check the size against
 */
export function validateRawSize(raw: Uint8Array, code: string = SAIDDex.Blake3_256) {
  const rize = rawSize(code)
  raw = raw.slice(0, rize)
  if (raw.length != rize) {
    throw new Error(
      `Not enough raw bytes for code ${code}. Expected ${rize} got ${raw.length}.`,
    )
  }
}

/**
 * SAIDifies arbitrary data passed in as a map (Dict) object.
 * Defaults to using the customary letter `d` as the label. The 'd' stands for digest.
 * Defaults to using Blake3-256 as the derivation algorithm and JSON as the serialization kind.
 *
 * Returns a tuple of [said, saidified data]
 *   - said: Self-addressing identifier; the fully qualified Base64 SAID
 *   - sad: Self-addressing data; the data object with the SAID added to the field labeled by `label`
 *
 * @example
 *
 * ```ts
 *   const myData = {
 *     a: 1,
 *     b: 2,
 *     d: ''
 *   }
 *   const label = 'd';
 *   const said = deriveSAIDBytes(myData, label);
 *   console.log(said);
 *   expect(said).toEqual('ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz');
 * ```
 *
 * @param data - data to derive self-addressing data from and to add to as a prop labeled by `label`
 * @param label - name of the property in the "data" field that will have the SAID placed inside
 * @param code - algorithm to be used to derive the SAID
 * @param kind - type of serialization to use
 */
export function saidify(
  data: Dict<any>,
  label: string = 'd',
  code: string = SAIDDex.Blake3_256,
  kind: Serials = Serials.JSON,
): [string, Dict<any>] {
  const [raw, sad] = deriveSAIDBytes(data, code, kind, label)
  const said = qb64(raw, code)
  sad[label] = said
  return [said, sad]
}

/**
 * Verifies a self-addressing data structure against a SAID. If the SAID is not supplied then the indicated
 * labeled field is used to read the SAID to use to verify the data.
 *
 * IMPORTANT: This assumes insertion-order preserving data structures. Newer versions of JavaScript/TypeScript
 * guarantee this but older versions do not.
 * If you are using an older version of JavaScript/TypeScript then this is currently unsupported as the
 * order of fields will not be deterministic.
 *
 * @example
 *
 * ```ts
 *   const myData = {
 *     a: 1,
 *     b: 2,
 *     d: 'ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz'
 *   }
 *   const label = 'd';
 *   const said = 'ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz';
 *   const doesVerify = verify(myData, label, said);
 *   // test assertion
 *   expect(doesVerify).toEqual(true);
 * ```
 *
 * @param sad - The self-addressing data to verify. Should contain the digest field labeled with the 'label' param.
 * @param label - The label of the self-addressing digest field, the SAID, in the self-addressing data 'sad' param.
 * @param said - The SAID to verify against. Defaults to the 'label' field of the 'sad' param.
 * @param code - The derivation code specifying which algorithm to use. Defaults to Blake3-256.
 * @param kind - The serialization kind to use. Defaults to JSON.
 * @param prefixed - Whether to verify the embedded SAID in the data structure against the computed qb64.
 * @param versioned - Whether to verify the version field in the data structure against the derived version field.
 */
export function verify(
  sad: Dict<any>,
  said?: string,
  label: string = 'd',
  code: string = SAIDDex.Blake3_256,
  kind: Serials = Serials.JSON,
  prefixed: boolean = false,
  versioned: boolean = false,
): boolean {
  if (sad[label] === undefined) {
    throw new Error(`Cannot verify self addressing data without digest field ${label}`)
  }
  // code = detectCode(data)
  const [raw, derivedSad] = deriveSAIDBytes(sad, code, kind, label)
  if (prefixed && sad[label] !== said) {
    return false
  }
  if ('v' in sad && versioned) {
    if (sad['v'] !== derivedSad['v']) {
      return false
    }
  }
  if (said) {
    return said === qb64(raw, code)
  } else {
    return sad[label] === qb64(raw, code)
  }
}
