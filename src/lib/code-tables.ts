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
   * Full Size (fs) - character count of the concatenation of the fixed (hard), variable (soft), and value parts of an
   * encoded primitive.
   * Will be -1 for variable size codes to indicate that the size is not fixed.
   *
   * fs = hs + ss + vs
   */
  fs: number
  /**
   * Lead Size (ls) - byte count of pre-padded, raw binary zero bytes.
   */
  ls: number
}

/**
 * An entry in the sizes table describing derivation code character and byte counts.
 */
export class Sizeage implements CodeCounts {
  constructor(
    public hs: number,
    public ss: number,
    public fs: number,
    public ls: number,
  ) {
  }
}

/**
 * Valid size codes for SAID derivations keyed by derivation code letter.
 */
export const Sizes = new Map(
  Object.entries({
    E: new Sizeage(1, 0, 44, 0), // Blake3 256 bit digest self-addressing derivation.
    F: new Sizeage(1, 0, 44, 0), // Blake2b 256 bit digest self-addressing derivation.
    I: new Sizeage(1, 0, 44, 0), // SHA2 256 bit digest self-addressing derivation.
    H: new Sizeage(1, 0, 44, 0), // SHA3 256 bit digest self-addressing derivation.
  }),
)
