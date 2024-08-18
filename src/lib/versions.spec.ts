import { describe, expect, it } from 'vitest'
import * as Lib from '../index.js'
import { Protocols } from '../index.js'

describe('versify CESR v1 serialize and deserialize version string', () => {
  it(`produces correct default version string with no args`, () => {
    let vs = Lib.versify()
    expect(vs).toEqual('KERI10JSON000000_')
    expect(vs.length).toEqual(Lib.VER1FULLSPAN)

    let [proto, vrsn, kind, size] = Lib.deversify(vs)
    expect(proto).toEqual(Lib.Protocols.KERI)
    expect(vrsn).toEqual(Lib.Vrsn_1_0)
    expect(kind).toEqual(Lib.Serials.JSON)
    expect(size).toEqual(0)
  })

  it(`produces a correct version string with JSON and size 65 (hex 41)`, () => {
    const vs = Lib.versify(Protocols.KERI, Lib.Vrsn_1_0, Lib.Serials.JSON, 65)
    expect(vs).toEqual('KERI10JSON000041_')
    expect(vs.length).toEqual(Lib.VER1FULLSPAN)

    let [proto, vrsn, kind, size] = Lib.deversify(vs)
    expect(proto).toEqual(Lib.Protocols.KERI)
    expect(vrsn).toEqual(Lib.Vrsn_1_0)
    expect(kind).toEqual(Lib.Serials.JSON)
    expect(size).toEqual(65)
  })

  it(`produces a correct ACDC version string with JSON and size 86`, () => {
    const vs = Lib.versify(Protocols.ACDC, Lib.Vrsn_1_0, Lib.Serials.JSON, 86)
    expect(vs).toEqual('ACDC10JSON000056_')
    expect(vs.length).toEqual(Lib.VER1FULLSPAN)

    let [proto, vrsn, kind, size] = Lib.deversify(vs)
    expect(proto).toEqual(Lib.Protocols.ACDC)
    expect(vrsn).toEqual(Lib.Vrsn_1_0)
    expect(kind).toEqual(Lib.Serials.JSON)
    expect(size).toEqual(86)
  })

  it(`produces a correct version string with CBOR and size 255 (hex FF)`, () => {
    const vs = Lib.versify(Protocols.KERI, Lib.Vrsn_1_0, Lib.Serials.CBOR, 255)
    expect(vs).toEqual('KERI10CBOR0000ff_')
    expect(vs.length).toEqual(Lib.VER1FULLSPAN)

    let [proto, vrsn, kind, size] = Lib.deversify(vs)
    expect(proto).toEqual(Lib.Protocols.KERI)
    expect(vrsn).toEqual(Lib.Vrsn_1_0)
    expect(kind).toEqual(Lib.Serials.CBOR)
    expect(size).toEqual(255)
  })

  it(`produces a correct version string with MGPK and size 256 (hex 100)`, () => {
    const vs = Lib.versify(Protocols.KERI, Lib.Vrsn_1_0, Lib.Serials.MGPK, 256)
    expect(vs).toEqual('KERI10MGPK000100_')
    expect(vs.length).toEqual(Lib.VER1FULLSPAN)

    let [proto, vrsn, kind, size] = Lib.deversify(vs)
    expect(proto).toEqual(Lib.Protocols.KERI)
    expect(vrsn).toEqual(Lib.Vrsn_1_0)
    expect(kind).toEqual(Lib.Serials.MGPK)
    expect(size).toEqual(256)
  })

  it(`produces a correct version string for KERI 1.1 with JSON and size 4095 (hex fff)`, () => {
    const vs = Lib.versify(Protocols.KERI, Lib.Vrsn_1_1, Lib.Serials.JSON, 4095)
    expect(vs).toEqual('KERI11JSON000fff_')
    expect(vs.length).toEqual(Lib.VER1FULLSPAN)

    let [proto, vrsn, kind, size] = Lib.deversify(vs)
    expect(proto).toEqual(Lib.Protocols.KERI)
    expect(vrsn).toEqual(Lib.Vrsn_1_1)
    expect(kind).toEqual(Lib.Serials.JSON)
    expect(size).toEqual(4095)
  })
})

describe(`versify CESR v2 serialize and deserialize version string`, () => {
  it(`produces a correct version string for KERI 2.0 (Base64URLSafe C = 2 AA == 0) with JSON and size 0 (Base64URLSafe AAAA)`, () => {
    const vs = Lib.versify(Protocols.KERI, Lib.Vrsn_2_0, Lib.Serials.JSON, 0)
    // KERI = protocol
    // C = 2 in Base64
    // AA = 0 in Base64 (padded to two chars)
    // JSON = serialization type
    // AAAA = primitive size 0 in Base64 (padded to four chars)
    expect(vs).toEqual('KERICAAJSONAAAA.')
    expect(vs.length).toEqual(Lib.VER2FULLSPAN)

    let [proto, vrsn, kind, size] = Lib.deversify(vs)
    expect(proto).toEqual(Lib.Protocols.KERI)
    expect(vrsn).toEqual(Lib.Vrsn_2_0)
    expect(kind).toEqual(Lib.Serials.JSON)
    expect(size).toEqual(0)
  })

  it(`produces a correct version string for KERI 2.0 with JSON and size 65 (Base64URLSafe AABB)`, () => {
    const vs = Lib.versify(Protocols.KERI, Lib.Vrsn_2_0, Lib.Serials.JSON, 65)
    expect(vs).toEqual('KERICAAJSONAABB.')
    expect(vs.length).toEqual(Lib.VER2FULLSPAN)

    let [proto, vrsn, kind, size] = Lib.deversify(vs)
    expect(proto).toEqual(Lib.Protocols.KERI)
    expect(vrsn).toEqual(Lib.Vrsn_2_0)
    expect(kind).toEqual(Lib.Serials.JSON)
    expect(size).toEqual(65)
  })

  it(`produces a correct version string for ACDC 2.0 with CBOR and size 86 (Base64URLSafe AABW)`, () => {
    const vs = Lib.versify(Protocols.ACDC, Lib.Vrsn_2_0, Lib.Serials.CBOR, 86)
    expect(vs).toEqual('ACDCCAACBORAABW.')
    expect(vs.length).toEqual(Lib.VER2FULLSPAN)

    let [proto, vrsn, kind, size] = Lib.deversify(vs)
    expect(proto).toEqual(Lib.Protocols.ACDC)
    expect(vrsn).toEqual(Lib.Vrsn_2_0)
    expect(kind).toEqual(Lib.Serials.CBOR)
    expect(size).toEqual(86)
  })

  // generate a test with mgpk and size 65
  it(`produces a correct version string for KERI 2.0 with MGPK and size 65 (Base64URLSafe AABB)`, () => {
    const vs = Lib.versify(Protocols.KERI, Lib.Vrsn_2_0, Lib.Serials.MGPK, 65)
    expect(vs).toEqual('KERICAAMGPKAABB.')
    expect(vs.length).toEqual(Lib.VER2FULLSPAN)

    let [proto, vrsn, kind, size] = Lib.deversify(vs)
    expect(proto).toEqual(Lib.Protocols.KERI)
    expect(vrsn).toEqual(Lib.Vrsn_2_0)
    expect(kind).toEqual(Lib.Serials.MGPK)
    expect(size).toEqual(65)
  })
})
