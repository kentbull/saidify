The shell for this project was generated from the [template](https://github.com/jasonkuhrt/template-typescript-lib) by [Jason Kurht](https://kuhrt.me/about/).

Features:

- Modules: Hybrid ESM/CJS
- Types: TypeScript
- Tests: Vitest
- Linting: ESLint
- Formatting: dprint
- Publishing: Dripip
- Continuous Integration: GitHub Actions
- Dependency Management: Renovate
- Community: Issue Templates

## Details

<!-- toc -->

- [TypeScript](#typescript)
- [ESLint](#eslint)
- [Vitest](#vitest)
- [Dripip](#dripip)
- [Simple succinct friendly low-barrier issue templates](#simple-succinct-friendly-low-barrier-issue-templates)
- [dprint](#dprint)
- [npm scripts for development lifecycle](#npm-scripts-for-development-lifecycle)
- [CI with GitHub Actions](#ci-with-github-actions)
- [Renovate](#renovate)
- [PnPM](#pnpm)
- [CJS+ESM Hybrid package build](#cjsesm-hybrid-package-build)
- [VSCode Settings](#vscode-settings)
- [Readme Table of Contents](#readme-table-of-contents)
- [Useful TypeScript Libraries](#useful-typescript-libraries)

<!-- tocstop -->

#### [TypeScript](https://www.typescriptlang.org/) for Type Safety & Productivity

1. Optimal settings for type safety via `@tsconfig/node18` and `@tsconfig/strictest`
1. `.tsbuildinfo` cache setup, output discretely into `node_modules/.cache`
1. Base `tsconfig.json` shared across `tests` and `src`.
1. Optimal output setup for your users

   1. [`declaration`](https://www.typescriptlang.org/tsconfig#declaration) so your users can power their intellisense with your packages typings.
   1. [`declarationMap`](https://www.typescriptlang.org/tsconfig#declarationMap) enabled to make your published source code be navigated to when your users use "go to definition".
   1. `package.json` [`typeVersions`](https://www.typescriptlang.org/docs/handbook/declaration-files/publishing.html#version-selection-with-typesversions) used to emit only **one** set of declaration files shared by both CJS and ESM builds.
   1. [`sourceMap`](https://www.typescriptlang.org/tsconfig#sourceMap) enabled to allow your users' tools to base off the source for e.g. stack traces instead of the less informative derived built JS.
   1. Publish `src` with build files so that jump-to-definition tools work optimally for users.

1. `tsx` for running TypeScript scripts/modules.

#### [ESLint](https://eslint.org/) For Linting

1. TypeScript integration
1. TS type-checker powered eslint checks enabled
1. Setup as a CI check for PRs
1. Always display as warning to keep IDE error feedback for TypeScript (CI enforces warnings).
1. Auto-fixable import sorting

#### [Vitest](https://vitest.dev) for Testing

Just Works :)

#### [Dripip](https://github.com/prisma-labs/dripip) for Releasing

#### Simple succinct friendly low-barrier issue templates

1. Emojis ✈️
1. Feature / bug / docs / something-else
1. Config to display discussions link right in new issue type listing UI

#### [dprint](https://dprint.dev/) for code formatting

1. Setup as a CI check for PRs
1. [VSCode extension](https://marketplace.visualstudio.com/items?itemName=dprint.dprint) in recommended extensions list so that when collaborators open the project they'll get prompted to install it if they haven't already.
1. npm script

#### npm scripts for development lifecycle

1. `clean` to remove cache and build files
1. `build` that runs `clean` beforehand
1. `prepublishOnly` that runs `build` beforehand
1. `format` to run `dprint` over whole codebase
1. `lint` to run `eslint` over whole codebase

#### CI with GitHub Actions

1. Separate trunk and pull-request (PR) workflows.
1. [Dependency install cache](https://github.com/actions/setup-node/blob/main/docs/advanced-usage.md#caching-packages-dependencies) enabled.
1. On PR:
   1. Formatting Check
   1. Lint Check
   1. Type Check
   1. Tests across matrix of mac/linux/windows for Node 14/16
1. On trunk:
   1. Tests across matrix of mac/linux/windows for Node 14/16
   1. Automated canary release

#### [Renovate](https://github.com/renovatebot/renovate) configuration

1. JSON Schema setup for optimal intellisense
1. Group all non-major devDependency updates into single PR (which "chore" conventional commit type)
1. Group all major devDependency updates into single PR (with "chore" conventional commit type)
1. Group all non-major dependency updates into single PR (with "deps" conventional commit type)
1. Each major dependency update in own PR (with "deps" conventional commit type)

#### [PnPM](https://pnpm.io/) for package management

1. Using [Corepack](https://nodejs.org/api/corepack.html#enabling-the-feature). This means the PnPM specified in `package.json` will be used. And note this is a PnPM binary shipped with Node now. In a future version of Node you will not need to even opt-in into Corepack. Make sure you've done `corepack enable` at least once.

#### CJS+ESM Hybrid package build

An [actually working](https://kuhrt.me/logs/hybrid-esm-cjs-node-packages-using-typescript-take-2) hybrid CJS/ESM build.

#### VSCode Settings

1. Optimize project search by recursively (ready for monorepo) ignoring `build/*`, snapshots, lock files, and more.
1. On-Save actions for optimal editing experience (e.g. ESLint auto-fix to [organize imports automatically](https://github.com/lydell/eslint-plugin-simple-import-sort#can-i-use-this-without-autofix))
1. List of VSCode extensions that users who open the project will be prompted to install if they don't already.
1. Enable `typescript.enablePromptUseWorkspaceTsdk` so that oneself and collaborators will get prompted to use the workspace version of TypeScript instead of the one in the editor.

#### Readme Table of Contents

1. Using [`markdown-toc`](https://github.com/jonschlinkert/markdown-toc)
