import { blake2b } from '@noble/hashes/blake2b'
import { blake3 } from '@noble/hashes/blake3'
import { sha256 } from '@noble/hashes/sha256'
import { sha3_256 } from '@noble/hashes/sha3'

/**
 * A base class for lists of things
 */
export class Codex {
  /**
   * Check if a codex entry exists by checking both keys and values.
   * @param prop - The property to check for existence.
   */
  has(prop: string): boolean {
    const m = new Map(
      Array.from(Object.entries(this), (v) => [v[1], v[0]]),
    )
    return m.has(prop)
  }
}

/**
 * A list of supported algorithms for deriving self-addressing identifiers.
 */
export class SAIDAlgoCodex extends Codex {
  Blake3_256: string = 'E' // Blake3 256 bit digest self-addressing derivation.
  Blake2b_256: string = 'F' // Blake2b 256 bit digest self-addressing derivation.
  SHA2_256: string = 'I' // SHA2 256 bit digest self-addressing derivation.
  SHA3_256: string = 'H' // SHA3 256 bit digest self-addressing derivation.
}
export const SAIDDex = new SAIDAlgoCodex() // Create an instance of SAIDAlgoCodex

type DigestFn = (ser: Uint8Array) => Buffer

/**
 * A class for storing a digest function and its size (not default) and length.
 * Size and length are needed for some digest types as function parameters.
 */
class Digestage {
  /**
   * The digest function to use that calls the algorithm appropriate function.
   */
  public fn: DigestFn
  /**
   * An argument needed for some digest types.
   */
  public size?: number | undefined
  /**
   * An argument needed for some digest types.
   */
  public length?: number | undefined
  constructor(fn: DigestFn, size?: number, length?: number) {
    this.fn = fn
    this.size = size
    this.length = length
  }
}

export const DigestAlgoMap = new Map<string, Digestage>([
  [SAIDDex.Blake3_256, new Digestage(deriveBlake3_256, 32, 0)],
  [SAIDDex.Blake2b_256, new Digestage(deriveBlake2b_256, 32, 0)],
  [SAIDDex.SHA2_256, new Digestage(deriveSHA2_256, 32, 0)],
  [SAIDDex.SHA3_256, new Digestage(deriveSHA3_256, 32, 0)],
])

function deriveBlake3_256(ser: Uint8Array): Buffer {
  return Buffer.from(blake3(ser, { dkLen: 32 }))
}

function deriveBlake2b_256(ser: Uint8Array): Buffer {
  return Buffer.from(blake2b(ser, { dkLen: 32 }))
}

function deriveSHA2_256(ser: Uint8Array): Buffer {
  return Buffer.from(sha256(ser))
}

function deriveSHA3_256(ser: Uint8Array): Buffer {
  return Buffer.from(sha3_256(ser))
}
