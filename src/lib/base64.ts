/**
 * A map of all Base64URLSafe indexes to characters from 0-63. Includes A-Z, a-z, 0-9, -, and _
 */
export const B64ChrByIdx = new Map<number, string>([
  [0, 'A'],
  [1, 'B'],
  [2, 'C'],
  [3, 'D'],
  [4, 'E'],
  [5, 'F'],
  [6, 'G'],
  [7, 'H'],
  [8, 'I'],
  [9, 'J'],
  [10, 'K'],
  [11, 'L'],
  [12, 'M'],
  [13, 'N'],
  [14, 'O'],
  [15, 'P'],
  [16, 'Q'],
  [17, 'R'],
  [18, 'S'],
  [19, 'T'],
  [20, 'U'],
  [21, 'V'],
  [22, 'W'],
  [23, 'X'],
  [24, 'Y'],
  [25, 'Z'],
  [26, 'a'],
  [27, 'b'],
  [28, 'c'],
  [29, 'd'],
  [30, 'e'],
  [31, 'f'],
  [32, 'g'],
  [33, 'h'],
  [34, 'i'],
  [35, 'j'],
  [36, 'k'],
  [37, 'l'],
  [38, 'm'],
  [39, 'n'],
  [40, 'o'],
  [41, 'p'],
  [42, 'q'],
  [43, 'r'],
  [44, 's'],
  [45, 't'],
  [46, 'u'],
  [47, 'v'],
  [48, 'w'],
  [49, 'x'],
  [50, 'y'],
  [51, 'z'],
  [52, '0'],
  [53, '1'],
  [54, '2'],
  [55, '3'],
  [56, '4'],
  [57, '5'],
  [58, '6'],
  [59, '7'],
  [60, '8'],
  [61, '9'],
  [62, '-'],
  [63, '_'],
])

/**
 * A map of all Base64URLSafe characters to indexes. This is a reversal of B64ChrByIdx for lookup convenience.
 */
export const B64IdxByChr = new Map<string, number>(
  Array.from(B64ChrByIdx, (entry) => [entry[1], entry[0]]),
)

/**
 * Returns conversion of Base64 string to integer
 * @param s - the string to convert
 */
export function b64ToInt(s: string): number {
  if (s.length == 0) {
    throw new Error('Empty string, conversion undefined.')
  }

  let i = 0
  const rev = s.split('').reverse()
  rev.forEach((c: string, e: number) => {
    i |= B64IdxByChr.get(c)! << (e * 6)
  })

  return i
}

/**
 * Returns conversion of integer to Base64 string
 * @param i - the number to convert
 * @param l - the minimum number of Base64 digits left padded with Base64 0, or 'A', characters
 */
export function intToB64(i: number, l = 1): string {
  let out = ''
  while (l != 0) {
    out = B64ChrByIdx.get(i % 64) + out
    i = Math.floor(i / 64)
    if (i == 0) {
      break
    }
  }

  const x = l - out.length
  for (let i = 0; i < x; i++) {
    out = 'A' + out
  }

  return out
}
