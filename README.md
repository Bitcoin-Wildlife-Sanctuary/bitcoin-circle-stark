<div align="center">
  
<a href="https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark/actions/workflows/test.yml"><img alt="GitHub Workflow Status (with event)" src="https://img.shields.io/github/actions/workflow/status/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark/test.yml?style=for-the-badge&logo=bitcoin" height=30></a>
<a href="https://codecov.io/gh/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark" >
<img src="https://img.shields.io/codecov/c/github/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark?style=for-the-badge&logo=codecov" height=30/>
</a>
<a href="https://securityscorecards.dev/viewer/?uri=github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark"><img alt="OpenSSF Scorecard Report" src="https://img.shields.io/ossf-scorecard/github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark?label=openssf%20scorecard&style=for-the-badge" height=30></a>
<a href="https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark.svg?style=for-the-badge" alt="Project license" height="30"></a>
<a href="https://twitter.com/bitcoinwildlife"><img src="https://img.shields.io/twitter/follow/bitcoinwildlife?style=for-the-badge&logo=twitter" alt="Follow bitcoinwildlife on Twitter" height="30"></a>

</div>

## Circle STARK Verifier in Bitcoin Script

This repository includes Bitcoin script implements a Circle Plonk verifier in Bitcoin script, consisting of reusable 
components.

### Building Blocks

- **M31, CM31, QM31, Circle Point**: implementation of add, sub, mul of Mersenne-31 (M31) and its complex extension (CM31) and its degree-4 extension (QM31), 
    and specifically table-based mul and non-table-based mul, and implementation of add, sub, mul of circle points, which are over the circle curve `x^2 + y^2 = 1`.
- **Fiat-Shamir Transcript**: aka "channel", which is the name used in Starkware's [stwo](https://github.com/starkware-libs/stwo) library, which supports absorbing and squeezing elements for Fiat-Shamir transform using hints and `OP_CAT + OP_SHA256`.
- **Proof-of-Work Check**: verifying the proof-of-work used in FRI-based protocols.
- **FRI**: implementation of the FRI quotient polynomial and the protocol for FRI low-degree testing.
- **Merkle Tree**: implementation of Merkle path verification using hints and `OP_CAT + OP_SHA256`.

---

### License and contributors

This repository is intended to be public good. It is under the MIT license. 

A portion of the code is contributed by [L2 Iterative (L2IV)](https://www.l2iterative.com/), a crypto 
VC based in San Francisco and Hong Kong. The work receives support from Starkware, who is a limited partner in L2IV. For 
disclosure, L2IV has also invested into numerous companies active in the Bitcoin ecosystem, but this work is open-source 
and nonprofit, and is not intended for competition. The code is not investment advice.

Starkware contributes a portion of the code, including the original Rust FRI implementation (from stwo) and some Bitcoin scripts.

There are also community members contributing to the code and contributing to the ideas. Bitcoin Wildlife Sanctuary is a 
public-good project supported by many people. 

Below we reiterate the contributors to this repository.

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/victorkstarkware"><img src="https://avatars.githubusercontent.com/u/160594433?v=4?s=100" width="100px;" alt="victorkstarkware"/><br /><sub><b>victorkstarkware</b></sub></a><br /><a href="#code-victorkstarkware" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://starknet.io"><img src="https://avatars.githubusercontent.com/u/45264458?v=4?s=100" width="100px;" alt="Abdel @ StarkWare "/><br /><sub><b>Abdel @ StarkWare </b></sub></a><br /><a href="#maintenance-AbdelStark" title="Maintenance">🚧</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/features/security"><img src="https://avatars.githubusercontent.com/u/27347476?v=4?s=100" width="100px;" alt="Dependabot"/><br /><sub><b>Dependabot</b></sub></a><br /><a href="#security-dependabot" title="Security">🛡️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/PayneJoe"><img src="https://avatars.githubusercontent.com/u/6851723?v=4?s=100" width="100px;" alt="PayneJoe"/><br /><sub><b>PayneJoe</b></sub></a><br /><a href="#code-PayneJoe" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/januszgrze"><img src="https://avatars.githubusercontent.com/u/82240624?v=4?s=100" width="100px;" alt="janusz"/><br /><sub><b>janusz</b></sub></a><br /><a href="#review-januszgrze" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/dikel"><img src="https://avatars.githubusercontent.com/u/9680010?v=4?s=100" width="100px;" alt="Deyan Dimitrov"/><br /><sub><b>Deyan Dimitrov</b></sub></a><br /><a href="#code-dikel" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->
