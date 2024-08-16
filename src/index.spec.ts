import { expect, test } from 'vitest'
import * as Lib from './index.js'
import { SAIDDex, Serials } from './index.js'

test(`saidify produces a qb64`, () => {
  const sad = {
    d: ``,
    attr1: `value1`,
    attr2: `value2`,
    attr3: `value3`,
  }
  const label = `d`

  const said = Lib.saidify(sad, SAIDDex.Blake3_256, Serials.JSON, label)
  // TODO implement Matter._infil in order to verify the output
  expect(said).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
})
