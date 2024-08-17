import * as cbor from 'cbor'
import msgpack5 from 'msgpack5'
import { DigestAlgoMap, SAIDDex } from './digests.js'
import { toBytes } from './encoding.js'
import { deversify, versify, Version } from './versions.js'
import {encodeBase64Url} from "./base64.js";

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
 * Describes the various sizes of encoded cryptographic primitives including character and byte counts.
 * SAIDs are the only cryptographic primitive in this library. These code counts are used for what is
 * called the fully-qualified forms of an encoded SAID. This includes:
 * - The fully qualified Base64 form (qb64)
 * - The fully qualified Base2 (binary - qb2) form
 */
export interface CodeCounts {
  /**
   * Hard Size (hs) - character count of fixed part of code size
   */
  hs: number
  /**
   * Soft Size (ss) - character count of variable part of code size
   */
  ss: number
  /**
   * Lead Size (ls) - byte count of pre-padded, raw binary zero bytes.
   */
  ls: number
  /**
   * Full Size (fs) - character count of the concatenation of the fixed (hard), variable (soft), and value parts of an
   * encoded primitive.
   * Will be -1 for variable size codes to indicate that the size is not fixed.
   *
   * fs = hs + ss + vs
   */
  fs: number
}

/**
 * An entry in the sizes table describing derivation code character and byte counts.
 */
export class Sizeage implements CodeCounts {
  constructor(
    public hs: number,
    public ss: number,
    public ls: number,
    public fs: number,
  ) {}
}

/**
 * Valid size codes for SAID derivations keyed by derivation code letter.
 */
export const Sizes = new Map(
  Object.entries({
    E: new Sizeage(1, 0, 44, 0), // Blake3 256 bit digest self-addressing derivation.
    H: new Sizeage(1, 0, 44, 0), // SHA3 256 bit digest self-addressing derivation.
    I: new Sizeage(1, 0, 44, 0), // SHA2 256 bit digest self-addressing derivation.
  }),
)

/**
 * A dictionary object with string keys and any value type.
 */
export interface Dict<T> {
  [id: string]: T
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
 * Returns a typle of associated values extracted or changed by sizeify
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
 * SAIDifies arbitrary data passed in as a map (Dict) object.
 * Defaults to using the customary letter `d` as the label. The 'd' stands for digest.
 *
 * @example
 *
 * ```ts
 *   const myData = {
 *     a: 1,
 *     b: 2,
 *   }
 *   const label = 'd';
 *   const said = saidify(myData, label);
 *   console.log(said); // ELOaxFqMsS9NFeJiDpKTb3X-xJahjNbh13QoBPnSxMWV TODO update this with the correct SAID
 * ```
 *
 * @param data - data to derive self-addressing data from and to add to as a prop labeled by `label`
 * @param code - algorithm to be used to derive the SAID
 * @param kind - type of serialization to use
 * @param label - name of the property in the "data" field that will have the SAID placed inside
 */
export function saidify(
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
  const args: [number | undefined, number | undefined] = [undefined, undefined]
  if (digestage.size != undefined) {
    args.push(digestage.size)
  }
  if (digestage.length != undefined) {
    args.push(digestage.length)
  }

  return [digestage.fn(ser, ...args), data]
}

/**
 * Create a fully qualified Base64 representation of the raw bytes encoded as bytes.
 * This implementation only uses the hard part of the code as SAIDS do not have a variable part (soft size).
 *
 * @param raw - the raw bytes to encode
 * @param code - the algorithm derivation code to use
 * @param size - the expected size of the raw bytes
 */
export function qb64b(raw: Uint8Array, code: string = SAIDDex.Blake3_256, size: number): Uint8Array {
  const sizeage = Sizes.get(code)
  if (sizeage === undefined) {
    throw new Error(`Unsupported digest algorithm code = ${code}`)
  }
  const [hs, ss, fs, ls] = [sizeage.hs, sizeage.ss, sizeage.fs, sizeage.ls];
  const cs = hs + ss;
  const rs = raw.length;
  const ps = (3 - ((rs + ls) % 3)) % 3; // net pad size given raw size and lead size
  // net pad size must equal both code size remainder so that primitive both + converted padded raw is fs long.
  // Assumes ls in (0, 1, 2) and cs % 4 != 3, fs % 4 == 0. Sizes table must ensure these properties.
  // Even still, following check is a good idea.
  if (cs % 4 !== ps - sizeage.ls){
    throw new Error(`Invalid code size for ${code} and raw pad size ${ps} given raw length ${rs}`);
  }

  // Prepad raw so we midpad the full primitive. Prepadding with ps+ls zero bytes ensures encodeB64 of
  // prepad+lead+raw has no trailing pad characters. Finally skip first ps == cs % 4 of the converted characters
  // to ensure that when full code is prepended the full primitive size is fs but midpad bits are zeros.
  const prepad = new Uint8Array(ps + ls);
  const combined = new Uint8Array(prepad.length + raw.length);

  // fill out prepad
  // when fixed and ls != 0 then cs % 4 is zero and ps === ls
  // otherwise fixed and ls === 0 then cs % 4 === ps
  for (let i = 0; i < ps; i++) {
    prepad[i] = 0;
  }
  combined.set(prepad);
  // adjust the bytes considering padding
  combined.set(raw, prepad.length);

  return toBytes(code + encodeBase64Url(Buffer.from(combined)).slice(ps));
}

/**
 * Calculates the raw size in bytes not including the leader (leading pad bytes) for a given code.
 * Converts the Base64-encoded size back to the original byte size.
 *
 * @param code - the algorithm derivation code to calculate the raw size for
 */
export function rawSize(code: string = SAIDDex.Blake3_256): number {
  if(code.length === 0) {
    throw new Error('Invalid code, cannot calculate size.')
  }
  const sizeage = Sizes.get(code);

  if(sizeage === undefined) {
    throw new Error(`Unsupported digest algorithm code = ${code}`)
  }
  if(sizeage.fs === -1) {
    throw new Error(`Unsupported variable size code=${code}`)
  }

  const cs = sizeage.hs + sizeage.ss; // code size

  // converts a Base64-encoded size back to the original byte size
  // rize = raw size in bytes
  const rize = Math.floor(((sizeage.fs - cs) * 3) / 4)
    - sizeage.ls; // subtracting the lead pad bytes size (ls)
  return rize;
}

/**
 * Check whether the raw bytes contain enough content for the given derivation code algorithm.
 * @param raw - raw bytes to check
 * @param code - derivation code algorithm to check the size against
 */
export function validateRawSize(raw: Uint8Array, code: string = SAIDDex.Blake3_256) {
  const rize = rawSize(code);
  raw = raw.slice(0, rize)
  if (raw.length != rize) {
    throw new Error(
      `Not enough raw bytes for code ${code}. Expected ${rize} got ${raw.length}.`
    );
  }
}
