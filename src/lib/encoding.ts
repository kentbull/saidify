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

/**
 * Converts a number to hexadecimal and pads with empty bytes, or zeroes ('0') to length
 * @param value - the number to convert to hex
 * @param length - the length of the hex string, will be padded to meet length
 */
export function intToHex(value: number, length: number): string {
  return value.toString(16).padStart(length, '0')
}
