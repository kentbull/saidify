import * as cbor from 'cbor'
import msgpack5 from 'msgpack5'
import { b64ToInt, intToB64 } from './base64.js'
import { DigestAlgoMap, SAIDDex } from './digests.js'
import { intToHex, toBytes } from './encoding.js'

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
 * A version object with major and minor version numbers.
 */
export interface Versionage {
  major: number
  minor: number
}

/**
 * KERI Protocol version object with major and minor version numbers.
 */
export class Version implements Versionage {
  constructor(public major: number = 1, public minor: number = 0) {}
}
export const Vrsn_1_0 = new Version(1, 0)
export const Vrsn_2_0 = new Version(2, 0)

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

export const Sizes = new Map(
  Object.entries({
    E: new Sizeage(1, 0, 44, 0),
    H: new Sizeage(1, 0, 44, 0),
    I: new Sizeage(1, 0, 44, 0),
  }),
)

export interface Dict<T> {
  [id: string]: T
}

// Version string in JSON, CBOR, or MGPK field map serialization version 1
export const VER1FULLSPAN = 17 // number of characters in full version string
export const VER1TERM = `_`
export const VEREX1 = /([A-Z]{4})([0-9a-f])([0-9a-f])([A-Z]{4})([0-9a-f]{6})_/

// Version string in JSON, CBOR, or MGPK field map serialization version 2
export const VER2FULLSPAN = 16 // number of characters in full version string
export const VER2TERM = `.`
export const VEREX2 = /([A-Z]{4})([0-9A-Za-z_-])([0-9A-Za-z_-]{2})([A-Z]{4})([0-9A-Za-z_-]{4})\./

// Combined regular expression
export const VEREX = new RegExp(VEREX2.source + '|' + VEREX1.source)

export const Rever = new RegExp(VEREX)

/**
 * the result of smelling a version string
 *  proto (Protocols): protocol type value of Protocol. Examples: 'KERI', 'ACDC'
 *  vrsn (Version): protocol version named tuple (major, minor) of integers
 *  kind (Serials): serialization type value of Serials. Examples: 'JSON', 'CBOR', 'MGPK'
 *  size (number): integer size of raw serialization
 */
type Smellage = [Protocols, Version, Serials, number]

/**
 * Parse CESR version 1 regular expression matches from a version string.
 * @param match - the match array from the regular expression
 */
function parseVersion1Matches(match: RegExpMatchArray): Smellage {
  let proto: any
  let major: any
  let minor: any
  let version: Version = new Version()
  let kind: any
  let size: any
  const full = match[0]
  ;[proto, major, minor, kind, size] = [
    match[1],
    match[2],
    match[3],
    match[4],
    match[5],
  ]
  if (!Object.values(Protocols).includes(proto)) {
    throw new Error(`Invalid protocol ${kind} in string = ${full}`)
  }
  try {
    major = b64ToInt(major)
  } catch (e) {
    throw new Error(`Invalid major version ${major} in string = ${full}: ${e}`)
  }
  if (major < 2) {
    throw new Error(`Incompatible major version ${major} with string = ${full}`)
  }
  try {
    minor = b64ToInt(minor)
  } catch (e) {
    throw new Error(`Invalid minor version = ${minor}: ${e}`)
  }
  version.major = major
  version.minor = minor

  if (!Object.values(Serials).includes(kind)) {
    throw new Error(`Invalid serialization kind ${kind} in string = ${full}`)
  }
  try {
    size = b64ToInt(size)
  } catch (e) {
    throw new Error(`Invalid size = ${size}: ${e}`)
  }
  return [proto as Protocols, version, kind as Serials, size]
}

/**
 * Parse CESR version 2 regular expression matches from a version string.
 * @param match - the match array from the regular expression
 */
function parseVersion2Matches(match: RegExpMatchArray): Smellage {
  let proto: any
  let major: any
  let minor: any
  let version: Version = new Version()
  let kind: any
  let size: any
  const full = match[0]
  ;[proto, major, minor, kind, size] = [
    match[1],
    match[2],
    match[3],
    match[4],
    match[5],
  ]
  if (!Object.values(Protocols).includes(proto)) {
    throw new Error(`Invalid protocol ${kind} in string = ${full}`)
  }
  try {
    major = parseInt(major, 16)
  } catch (e) {
    throw new Error(`Invalid major version ${major} in string = ${full}: ${e}`)
  }
  if (major < 2) {
    throw new Error(`Incompatible major version ${major} with string = ${full}`)
  }
  try {
    minor = parseInt(minor, 16)
  } catch (e) {
    throw new Error(`Invalid minor version = ${minor}: ${e}`)
  }
  version.major = major
  version.minor = minor

  if (!Object.values(Serials).includes(kind)) {
    throw new Error(`Invalid serialization kind ${kind} in string = ${full}`)
  }
  try {
    size = parseInt(size, 16)
  } catch (e) {
    throw new Error(`Invalid size = ${size}: ${e}`)
  }
  return [proto as Protocols, version, kind as Serials, size]
}

/**
 * Regular expression matcher for the CESR version string
 * @param match - the match array from the regular expression
 */
export function rematch(match: RegExpMatchArray): Smellage {
  const full = match[0]
  if (full.length === VER2FULLSPAN && full[full.length - 1] === VER2TERM) {
    return parseVersion2Matches(match)
  } else if (full.length === VER1FULLSPAN && full[full.length - 1] === VER1TERM) {
    return parseVersion1Matches(match)
  } else {
    throw new Error(`Invalid version string = ${full}`)
  }
}

/**
 * Deserializes a Version from a string
 * @param versionString - the version string to deserialize
 * returns Smellage a tuple of protocol, version, serialization, and size
 */
export function deversify(versionString: string): Smellage {
  const match = Rever.exec(versionString)
  if (!match) {
    throw new Error(`Invalid version string = ${versionString}`)
  }
  return rematch(match)
}

const VERRAWSIZE = 6

/**
 * Generates a version string from a protocol, version, serialization, and size
 * @param protocol - the protocol to use
 * @param version - the version of the protocol to use
 * @param kind - the type of serialization to use
 * @param size - the size of the serialized data
 */
export function versify(
  protocol: Protocols = Protocols.KERI,
  version: Version = Vrsn_1_0,
  kind: Serials = Serials.JSON,
  size: number = 0,
) {
  if (version.major < 2) {
    const major = intToHex(version.major, 0)
    const minor = intToHex(version.minor, 0)
    const formattedSize = intToHex(size, VERRAWSIZE)
    return `${protocol}${major}${minor}${kind}${formattedSize}${VER1TERM}`
  } else {
    const major = intToB64(version.major)
    const minor = intToB64(version.minor)
    const formattedSize = intToB64(size, VERRAWSIZE)
    return `${protocol}${major}${minor}${kind}${formattedSize}${VER2TERM}`
  }
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
