import { beforeEach, describe, expect, it } from 'vitest'
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
    const saidDataCode = Lib.saidify(data, 'd', code)
    expect(saidDataCode).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })

  it(`produces a valid SAID for Blake3-256 and JSON with data and kind arg`, () => {
    const saidDataCodeKind = Lib.saidify(data, 'd', code, kind)
    expect(saidDataCodeKind).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })

  it(`produces a valid SAID for Blake3-256 and JSON with data, code, kind, and label arg`, () => {
    const saidAllArgs = Lib.saidify(data, label, code, kind)
    expect(saidAllArgs).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })

  it(`produces a valid SAID for Blake2b-256 and JSON with data, code, kind, and label arg`, () => {
    const saidAllArgs = Lib.saidify(data, label, code=SAIDDex.Blake2b_256, kind)
    expect(saidAllArgs).toEqual(`FIzy6Co4x-ynSoF7syuL15Vf82PxldUz05iTGPqiG31u`)
  })

  it(`produces a valid SAID for SHA2-256 and JSON with data, code, kind, and label arg`, () => {
    const saidAllArgs = Lib.saidify(data, label, code=SAIDDex.SHA2_256, kind)
    expect(saidAllArgs).toEqual(`IOwKVs_pD6kKKw1_eHXI4CUfRfw4mBpvlUuIDdZQXoPr`)})

  it(`produces a valid SAID for SHA3-256 and JSON with data, code, kind, and label arg`, () => {
    const saidAllArgs = Lib.saidify(data, label, code=SAIDDex.SHA3_256, kind)
    expect(saidAllArgs).toEqual(`HLL3GkCKe6HnqkP4ENBWjLlAQVR6Agsw7TVNToyn0lk3`)
  })
})

describe('example code tests', () => {
  it(`README and JSDoc code test`, () => {
    const data = {
      a: 1,
      b: 2,
      d: '',
    }
    const label = 'd'
    const said = Lib.saidify(data, label, SAIDDex.Blake3_256, Serials.JSON)
    expect(said).toEqual('ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz')
  })
})

describe(`verify function tests`, () => {
  it(`should verify when only self-addressing data structure passed in`, () => {
    const data = {
      a: 1,
      b: 2,
      d: 'ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz',
    }
    const doesVerify = Lib.verify(data)
    expect(doesVerify).toEqual(true)
  })

  it(`should verify self-addressing data against the SAID`, () => {
    const said = 'ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz'
    const data = {
      a: 1,
      b: 2,
      d: 'ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz',
    }
    const doesVerify = Lib.verify(data, said)
    expect(doesVerify).toEqual(true)
  })

  it(`should verify a self-addressing data structure and it's labeled SAID field against a SAID`, () => {
    const said = 'ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz'
    const data = {
      a: 1,
      b: 2,
      d: 'ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz',
    }
    const label = 'd'
    const doesVerify = Lib.verify(data, said, label)
    expect(doesVerify).toEqual(true)
  })
})
