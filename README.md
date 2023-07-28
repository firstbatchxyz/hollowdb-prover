<p align="center">
  <img src="./logo.svg" alt="logo" width="142">
</p>

<p align="center">
  <h1 align="center">
    HollowDB Prover
  </h1>
  <p align="center">
    <i>Proof generator package for HollowDB.</i>
  </p>
</p>

<p align="center">
    <a href="https://opensource.org/licenses/MIT" target="_blank">
        <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-yellow.svg">
    </a>
    <a href="https://www.npmjs.com/package/hollowdb-prover" target="_blank">
        <img alt="NPM" src="https://img.shields.io/npm/v/hollowdb-prover?logo=npm&color=CB3837">
    </a>
    <a href="https://docs.hollowdb.xyz" target="_blank">
        <img alt="License: MIT" src="https://img.shields.io/badge/docs-hollowdb-3884FF.svg?logo=gitbook">
    </a>
    <a href="./.github/workflows/test.yml" target="_blank">
        <img alt="Workflow: Tests" src="https://github.com/firstbatchxyz/hollowdb-prover/actions/workflows/test.yml/badge.svg?branch=master">
    </a>
    <a href="https://github.com/firstbatchxyz/hollowdb" target="_blank">
        <img alt="GitHub: HollowDB" src="https://img.shields.io/badge/github-hollowdb-5C3EFE?logo=github">
    </a>
    <a href="https://discord.gg/2wuU9ym6fq" target="_blank">
        <img alt="Discord" src="https://dcbadge.vercel.app/api/server/2wuU9ym6fq?style=flat">
    </a>
</p>

## Installation

HollowDB prover is an NPM package. You can install it as:

```sh
yarn add hollowdb-prover    # yarn
npm install hollowdb-prover # npm
pnpm add hollowdb-prover    # pnpm
```

## Usage

A `Prover` class is exported, where the user must provide path to circuit WASM and prover keys. You can find these files [here](./circuits/) in this repo, but you must place them to wherever you need during your application, e.g. under `public` directory on frontend, or some other directory on backend.

It also provides a `computeKey` function, which is simply a wrapper around the underlying Poseidon hash.

_More documentation soon._

## Testing

To run tests for both Groth16 and PLONK:

```sh
yarn test
```
