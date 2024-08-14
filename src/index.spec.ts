import { expect, test } from 'vitest'
import * as Lib from './index.js'

test(`saidify produces a qb64`, () => {
  const sad = {
    d: ``,
    attr1: `value1`,
    attr2: `value2`,
    attr3: `value3`,
  }
  const label = `d`

  const said = Lib.saidify(sad, label)
  // expect(said).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  expect(said).toEqual(`{"d":"","attr1":"value1","attr2":"value2","attr3":"value3"}-d`) // TODO update this with the correct SAID
})
