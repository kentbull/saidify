const encoder = new TextEncoder()
const decoder = new TextDecoder()

/**
 * Turn a UTF-8 encoded string into a byte array
 * @param s - string to convert
 */
export function toBytes(s?: string): Uint8Array {
  return encoder.encode(s)
}

/**
 * Turn a byte array into a UTF-8 encoded string
 * @param u - byte array to convert to string
 */
export function fromBytes(u?: Uint8Array): string {
  return decoder.decode(u)
}
