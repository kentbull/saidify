import { expect, test } from 'vitest'
import * as Lib from './index.js'
import { SAIDDex, Serials } from './index.js'

test(`saidify Blake3-256 of JSON produces a valid said`, () => {
  const data = {
    d: ``,
    attr1: `value1`,
    attr2: `value2`,
    attr3: `value3`,
  }
  const code = SAIDDex.Blake3_256
  const kind = Serials.JSON
  const label = `d`

  // TODO read rest of Saider.verify to see if I need anything else from it for SAID verification.

  const saidDataOnly = Lib.saidify(data)
  expect(saidDataOnly).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)

  const saidDataCode = Lib.saidify(data, code)
  expect(saidDataCode).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)

  const saidDataCodeKind = Lib.saidify(data, code, kind)
  expect(saidDataCodeKind).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)

  const saidAllArgs = Lib.saidify(data, code, kind, label)
  expect(saidAllArgs).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
})

test(`example code test`, () => {
  const data = {
    a: 1,
    b: 2,
    d: '',
  }
  const label = 'd'
  const said = Lib.saidify(data, SAIDDex.Blake3_256, Serials.JSON, label)
  expect(said).toEqual('ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz')
})
