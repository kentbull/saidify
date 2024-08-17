import { b64ToInt, intToB64 } from './base64.js'
import { Protocols, Serials } from './core.js'
import { intToHex } from './encoding.js'

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
  constructor(public major: number = 1, public minor: number = 0) {
  }
}

export const Vrsn_1_0 = new Version(1, 0)
export const Vrsn_2_0 = new Version(2, 0)
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
export type Smellage = [Protocols, Version, Serials, number]

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
