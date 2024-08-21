# SAIDify - (sēdəˌfī)

[![trunk](https://github.com/kentbull/saidify/actions/workflows/trunk.yaml/badge.svg)](https://github.com/kentbull/saidify/actions/workflows/trunk.yaml) [![codecov](https://codecov.io/github/kentbull/saidify/graph/badge.svg?token=4RX12XZKNF)](https://codecov.io/github/kentbull/saidify) [![npm version](https://badge.fury.io/js/saidify.svg)](https://badge.fury.io/js/saidify)

Generate self-addressing identifiers on arbitrary data.

## Usage

### Typescript

Install the package via NPM/PNPM:

```bash
npm install saidify
```

Import 'saidify' and SAIDify your data:

```typescript
import { saidify, verify } from 'saidify'

// create data to become self-addressing
const myData = {
  a: 1,
  b: 2,
  d: '',
}
const label = 'd'
const [said, sad] = saidify(myData, label)
// said is self-addressing identifier
// sad is self-addressing data
console.log(said)
// ...Vitest test assertion
expect(said).toEqual('ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz')

// verify self addressing identifier
const computedSAID = 'ELLbizIr2FJLHexNkiLZpsTWfhwUmZUicuhmoZ9049Hz'
const doesVerify = verify(sad, computedSAID, label) // can verify with original myData or sad
// ...Vitest test assertion
expect(doesVerify).toEqual(true)
```

You may find a full example Typescript project at [saidify-example](https://github.com/kentbull/saidify-example/blob/master/index.ts).

## Description

A self-addressing identifier (SAID) is a kind of content-addressable identifier that uses a two-pass approach to enable
embedding of the identifier in the content itself, thus the name self-addressing rather than content addressing.

A number of different specifications describe SAIDs.

- [ToIP CESR spec section: Self-addressing identifier (SAID)](https://trustoverip.github.io/tswg-cesr-specification/#self-addressing-identifier-said) - current
- [ToIP spec (archived) Self-Addressing IDentifier (SAID)](https://trustoverip.github.io/tswg-said-specification/draft-ssmith-said.html) - old

## Sources and References

- [signify-ts](https://github.com/WebOfTrust/signify-ts)
  - Most of the code in this repository is lifed from the SignifyTS project.
- [keripy](https://github.com/WebOfTrust/keripy)
  - Some of the code in this repository is inspired by KERIpy, the Python implementation of KERI.

## Development Statistics

![Alt](https://repobeats.axiom.co/api/embed/4e4bac4510f2c970e06c5998e2156589343445ed.svg "Repobeats analytics image")
