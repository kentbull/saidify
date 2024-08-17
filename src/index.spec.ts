import { beforeEach, describe, expect, it, test } from 'vitest'
import * as Lib from './index.js'
import { SAIDDex, Serials } from './index.js'

describe('saidify function tests', () => {
  let data: any
  let label: string
  let code: string
  let kind: Serials

  beforeEach(() => {
    data = {
      d: ``,
      attr1: `value1`,
      attr2: `value2`,
      attr3: `value3`,
    }
    code = SAIDDex.Blake3_256
    kind = Serials.JSON
    label = `d`
  })

  it(`produces a valid SAID for Blake3-256 algo and JSON serialization with only a data arg`, () => {
    const saidDataOnly = Lib.saidify(data)
    expect(saidDataOnly).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })

  it(`produces a valid SAID for Blake3-256 and JSON with data and code arg`, () => {
    const saidDataCode = Lib.saidify(data, code)
    expect(saidDataCode).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })

  it(`produces a valid SAID for Blake3-256 and JSON with data and kind arg`, () => {
    const saidDataCodeKind = Lib.saidify(data, code, kind)
    expect(saidDataCodeKind).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })

  it(`produces a valid SAID for Blake3-256 and JSON with data, code, kind, and label arg`, () => {
    const saidAllArgs = Lib.saidify(data, code, kind, label)
    expect(saidAllArgs).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })
})

describe('example code tests', () => {
  test(`README and JSDoc code test`, () => {
    const data = {
      a: 1,
      b: 2,
      d: '',
    }
    const label = 'd'
    const said = Lib.saidify(data, SAIDDex.Blake3_256, Serials.JSON, label)
    expect(said).toEqual('ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz')
  })
})
