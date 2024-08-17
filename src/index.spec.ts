import {expect, test} from 'vitest'
import * as Lib from './index.js'
import {qb64b, rawSize, SAIDDex, Serials, validateRawSize} from './index.js'
import {fromBytes} from "./lib/encoding.js";

test(`saidify produces a qb64`, () => {
  const sad = {
    d: ``,
    attr1: `value1`,
    attr2: `value2`,
    attr3: `value3`,
  }
  const label = `d`

  const code = SAIDDex.Blake3_256;
  const [raw, _data] = Lib.saidify(sad, code, Serials.JSON, label);
  const size = rawSize(code);
  validateRawSize(raw, code); // TODO move this to a qb64 generation/encoding function
  const saidQb64 = fromBytes(qb64b(raw, code, size));
  // TODO implement Matter._infil in order to verify the output
  expect(saidQb64).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
})
