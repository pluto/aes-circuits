<h1 align="center">
  AES-GCM circom circuits
</h1>

<div align="center">
  <a href="https://github.com/pluto/aes-proof/graphs/contributors">
    <img src="https://img.shields.io/github/contributors/pluto/aes-proof?style=flat-square&logo=github&logoColor=8b949e&labelColor=282f3b&color=32c955" alt="Contributors" />
  </a>
  <a href="https://github.com/pluto/aes-proof/actions/workflows/test.yaml">
    <img src="https://img.shields.io/badge/tests-passing-32c955?style=flat-square&logo=github-actions&logoColor=8b949e&labelColor=282f3b" alt="Tests" />
  </a>
  <a href="https://github.com/pluto/aes-proof/actions/workflows/lint.yaml">
    <img src="https://img.shields.io/badge/lint-passing-32c955?style=flat-square&logo=github-actions&logoColor=8b949e&labelColor=282f3b" alt="Lint" />
  </a>
</div>

> [!WARNING]
> ⚠️ Repository No Longer Maintained ⚠️
>
> This repository has been archived and is no longer maintained.
All development has moved to the [noir-web-prover-circuits](github.com/pluto/noir-web-prover-circuits) repository under the Pluto organization.

## Overview

This repository contains an implementation of [AES-GCM](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf) in Circom. We have used circomkit to generate and test witnesses in the test files. We have also used to related rust code in the `src` generate test vectors from official cryptography libraries. The Circuits and circomkit tests are in the `circuits` directory.

#### Design Documents

- [AES-GCM deep dive](https://gist.github.com/thor314/53cdab54aaf16bdafd5ac936d5447eb8)

### Prerequisites

To use this repo, you need to install the `just` command runner:

```sh
cargo install just
# or use cargo binstall for fast install:
cargo binstall -y just

# install dependencies
just install
```

### Testing
Test witnesses are validated by circomkits tests. These can be run with:
`just circom-test`

## Testing Circom
Example commands for using circom-kit
```
just circom-test # test all circom tests 
just circom-testg TESTNAME # test a named test

# also see:
`npx circomkit`: circomkit commands
`npx circomkit compile <circuit>`: equiv to `circom --wasm ...`
`npx circomkit witness <circuit> <witness.json>`: equiv to call generate_witness.js
```

## License

Licensed under the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)

## Contributing

We welcome contributions to our open-source projects. If you want to contribute or follow along with contributor discussions, join our [main Telegram channel](https://t.me/pluto_xyz/1) to chat about Pluto's development.

Our contributor guidelines can be found in [CONTRIBUTING.md](./CONTRIBUTING.md). A good starting point is issues labelled 'bounty' in our repositories.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be licensed as above, without any additional terms or conditions.
