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
    const [said, _sad] = Lib.saidify(data)
    expect(said).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })

  it(`produces a valid SAID for Blake3-256 and JSON with data and code arg`, () => {
    const [said, _sad] = Lib.saidify(data, 'd', code)
    expect(said).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })

  it(`produces a valid SAID for Blake3-256 and JSON with data and kind arg`, () => {
    const [said, _sad] = Lib.saidify(data, 'd', code, kind)
    expect(said).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })

  it(`produces a valid SAID for Blake3-256 and JSON with data, code, kind, and label arg`, () => {
    const [said, _sad] = Lib.saidify(data, label, code, kind)
    expect(said).toEqual(`EHSOlNZzwiekacJenXM3qPNU9-07ic_G0ejn8hrA2lKQ`)
  })

  it(`produces a valid SAID for Blake2b-256 and JSON with data, code, kind, and label arg`, () => {
    const [said, _sad] = Lib.saidify(data, label, code = SAIDDex.Blake2b_256, kind)
    expect(said).toEqual(`FIzy6Co4x-ynSoF7syuL15Vf82PxldUz05iTGPqiG31u`)
  })

  it(`produces a valid SAID for SHA2-256 and JSON with data, code, kind, and label arg`, () => {
    const [said, _sad] = Lib.saidify(data, label, code = SAIDDex.SHA2_256, kind)
    expect(said).toEqual(`IOwKVs_pD6kKKw1_eHXI4CUfRfw4mBpvlUuIDdZQXoPr`)
  })

  it(`produces a valid SAID for SHA3-256 and JSON with data, code, kind, and label arg`, () => {
    const [said, _sad] = Lib.saidify(data, label, code = SAIDDex.SHA3_256, kind)
    expect(said).toEqual(`HLL3GkCKe6HnqkP4ENBWjLlAQVR6Agsw7TVNToyn0lk3`)
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
    const [said, _sad] = Lib.saidify(data, label, SAIDDex.Blake3_256, Serials.JSON)
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

  it(`Blake2b-256 SAID matches KERIpy`, () => {
    const keripySAID = 'FOZ5T-PCxuMDMkl-Vih1BAWcxox5OcclLaxtTcmZcYmr' // got from from KERIpy
    const data = {
      d: '',
      first: 'Sue',
      last: 'Smith',
      role: 'Founder',
    }
    const label = 'd'
    const code = SAIDDex.Blake2b_256
    const [newSaid, sadData] = Lib.saidify(data, label, code, Serials.JSON)
    expect(newSaid).toEqual(keripySAID)
    const doesVerify = Lib.verify(sadData, newSaid, label, code)
    expect(doesVerify).toEqual(true)
  })

  it(`SHA2-256 SAID matches KERIpy`, () => {
    const keripySAID = 'IFvJUGAb-3CR_i-34QIg0qJ12-Dnq27pDdgEo3icRdM1' // got from from KERIpy
    const data = {
      d: '',
      first: 'Sue',
      last: 'Smith',
      role: 'Founder',
    }
    const label = 'd'
    const code = SAIDDex.SHA2_256
    const [newSaid, sadData] = Lib.saidify(data, label, code, Serials.JSON)
    expect(newSaid).toEqual(keripySAID)
    const doesVerify = Lib.verify(sadData, newSaid, label, code)
    expect(doesVerify).toEqual(true)
  })

  it(`SHA3-256 SAID matches KERIpy`, () => {
    const keripySAID = 'HGQJ4vetZJ_DfufKM0YcTyBXHlR3LxHRu-tOckDHTDM3' // got from from KERIpy
    const data = {
      d: '',
      first: 'Sue',
      last: 'Smith',
      role: 'Founder',
    }
    const label = 'd'
    const code = SAIDDex.SHA3_256
    const [newSaid, sadData] = Lib.saidify(data, label, code, Serials.JSON)
    expect(newSaid).toEqual(keripySAID)
    const doesVerify = Lib.verify(sadData, newSaid, label, code)
    expect(doesVerify).toEqual(true)
  })
})
