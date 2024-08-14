/**
 * SAIDifies arbitrary data passed in as a map (Dict) object.
 * Defaults to using the customary letter `d` as the label. The 'd' stands for digest.
 *
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
 */
export interface Dict<T> {
  [id: string]: T;
}

export const saidify = (sad: Dict<any>, label: string = `d`): string => {
  return `${JSON.stringify(sad)}-${label}`;
}
