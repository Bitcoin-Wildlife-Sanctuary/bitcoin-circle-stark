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

This repository includes Bitcoin script implementations of various cryptographic primitives for STARK.

- **M31, CM31, QM31, Circle Point** 
  * implementation of add, sub, mul of Mersenne-31 (M31) and its complex extension (CM31) and its degree-4 extension (QM31), 
    which is imported from [BitVM/rust-bitcoin-m31-or-babybear](https://github.com/BitVM/rust-bitcoin-m31-or-babybear).
  * implementation of add, sub, mul of circle points, which are over the circle curve `x^2 + y^2 = 1`.
- **CirclePoint over QM31**
  * implementation of double of a circle point over QM31.
  * implementation of drawing a random point on the circle over QM31, which is useful for OODS.
  * implementation of addition of a circle point over QM31.
- **Constraints on the circle curve over QM31**
  * implementation of `coset_vanishing()` and `pair_vanishing()`.
- **Fiat-Shamir Transcript**
  * aka "channel", which is the name used in Starkware's [stwo](https://github.com/starkware-libs/stwo) library.
  * absorbing commitments and QM31 elements through `OP_CAT + OP_SHA256`.
  * squeezing random elements for Fiat-Shamir transform using hints and `OP_CAT + OP_SHA256`.
- **Proof-of-Work Check**
  * calculating a proof-of-work nonce for the "channel", based on specified security bits.
  * verifying the proof-of-work nonce and computing the new "channel" state.
- **Merkle Tree**
  * implementation of Merkle path verification using hints and `OP_CAT + OP_SHA256`.

The next step is to implement the FRI protocol, which reasons about the degree of a quotient polynomial.

---

### Performance

These performance numbers are obtained from `cargo test -- --nocapture` over commit [6e5c211](https://github.com/Bitcoin-Wildlife-Sanctuary/bitcoin-circle-stark/commit/6e5c211fb755428ab3492eac2e0dcd39c99482d6).

- **M31, QM31**
  * M31.add = 18 bytes, QM31.add = 84 bytes
  * M31.sub = 12 bytes, QM31.sub = 63 bytes
  * M31.mul = 1415 bytes, QM31.mul = 13321 bytes
  * M31.mul_by_constant = ~744 bytes, QM31.mul_by_m31_constant = ~2981 bytes
  * QM31.mul_by_m31 = 4702 bytes
  * QM31.commit = 7 bytes, QM31.from_hash = 250 bytes
  * 5M31.from_hash = 312 bytes
- **CirclePoint over QM31**
  * CirclePoint.double_x = 13505 bytes
  * CirclePoint.get_random_point = 40546 bytes
  * CirclePoint.add = 40542 bytes
  * CirclePoint.add_constant_point = ~21780 bytes
  * CirclePoint.add_constant_m31_point = ~9235 bytes
  * CirclePoint.add_x_only = 26791 bytes
- **Constraints on the circle curve over QM31**
  * Constraints.pair_vanishing_with_constant_m31_points = ~6195 bytes
  * Constraints.coset_vanishing(log_size=5) = 80827 bytes
  * Constraints.coset_vanishing(log_size=6) = 94332 bytes
  * Constraints.coset_vanishing(log_size=7) = 107837 bytes
  * Constraints.coset_vanishing(log_size=8) = 121342 bytes
  * Constraints.coset_vanishing(log_size=9) = 134847 bytes
- **Fiat-Shamir Transcript**
  * Channel.mix_digest = 2 bytes
  * Channel.mix_felts = 9 bytes per felt
  * Channel.squeeze_element_using_hint = 257 bytes (require 5 hint elements)
  * Channel.squeeze_5queries_using_hint = 1222 bytes (require 6 hint elements)
- **Proof-of-Work Check**
  * POW.verify_pow(1 bit) = 39 bytes
  * POW.verify_pow(2 bits) = 38 bytes
  * POW.verify_pow(3 bits) = 38 bytes
  * POW.verify_pow(4 bits) = 37 bytes
  * POW.verify_pow(5 bits) = 37 bytes
  * POW.verify_pow(6 bits) = 37 bytes
  * POW.verify_pow(7 bits) = 37 bytes
  * POW.verify_pow(8 bits) = 21 bytes
  * POW.verify_pow(9 bits) = 42 bytes
  * POW.verify_pow(10 bits) = 41 bytes
  * POW.verify_pow(11 bits) = 41 bytes
  * POW.verify_pow(12 bits) = 40 bytes
  * POW.verify_pow(13 bits) = 40 bytes
  * POW.verify_pow(14 bits) = 40 bytes
  * POW.verify_pow(15 bits) = 40 bytes
  * POW.verify_pow(16 bits) = 22 bytes
  * POW.verify_pow(17 bits) = 43 bytes
  * POW.verify_pow(18 bits) = 42 bytes
  * POW.verify_pow(19 bits) = 42 bytes
  * POW.verify_pow(20 bits) = 41 bytes
- **Merkle tree**
  * MT.verify(2^12) = 263 bytes (require 11 hint elements)
  * MT.verify(2^14) = 309 bytes (require 13 hint elements)
  * MT.verify(2^16) = 356 bytes (require 15 hint elements)
  * MT.verify(2^18) = 404 bytes (require 18 hint elements)
  * MT.verify(2^20) = 452 bytes (require 20 hint elements)

---

### Channel

The channel is used for Fiat-Shamir transform. It absorbs elements that are either prior knowledge of the verifier or provers' 
messages, and it can be squeezed to produce pseudorandom elements. There are five operations.

- `new(digest) -> channel`: initialize a new channel using an initial digest
  * `channel := digest`
- `mix_digest(channel, digest) -> channel'`: update the channel with a digest
  * `channel' := SHA256(channel || commitment)`
- `mix_felts(channel, [qm31]) -> channel'`: update the channel with QM31 elements
  * `channel' := SHA256(channel || commit(qm31))` for each qm31
- `squeeze(channel) -> (qm31, channel')`: squeeze a QM31 element out of the channel
  * `hash := SHA256(channel || 0x00)`
  * `channel' := SHA256(channel)`
  * `qm31 := extract(hash)`
- `squeeze(channel, logn) -> (q1, q2, q3, q4, q5, channel')`: squeeze five positions on a list of 2^logn elements
  * `hash := SHA256(channel || 0x00)`
  * `channel' := SHA256(channel)`
  * `q1, q2, q3, q4, q5 := extract(hash, logn)`

The constructions of commit and extract are as follows.

**Commit.** With `OP_CAT + OP_SHA256`, we can commit QM31 elements with a few bytes.

QM31 requires 7 bytes: `commit(qm31) := SHA256(qm31.0.0 || SHA256(qm31.0.1 || SHA256(qm31.1.0 || SHA256(qm31.1.1))))`
```
OP_SHA256 OP_CAT OP_SHA256 OP_CAT OP_SHA256 OP_CAT OP_SHA256
```

**Extract.** Since we do not have `OP_SUBSTR`, to extract a QM31 element or five positions from the hash, we need to use hints. The 
idea is to peel off the first few bytes of the hash and recreate a normalized QM31 element out of it. If we want to extract 
positions, the numbers are further adjusted to have only `logn` bits.

- For QM31, the hint includes five elements: 
  * `hash[0..4]` in the minimal number encoding form
  * `hash[4..8]` in the minimal number encoding form
  * `hash[8..12]` in the minimal number encoding form
  * `hash[12..16]` in the minimal number encoding form
  * `hash[16..32]` as bytes, which is the tail
- For five positions, the hint includes six elements:
  * `hash[0..4]` in the minimal number encoding form
  * `hash[4..8]` in the minimal number encoding form
  * `hash[8..12]` in the minimal number encoding form
  * `hash[12..16]` in the minimal number encoding form
  * `hash[16..20]` in the minimal number encoding form
  * `hash[20..32]` as bytes, which is the tail

Due to the minimal number encoding form, the hint element, which represents a signed 32-bit integer, does not necessarily 
have four bytes. Our solution is to use `OP_SIZE` to detect its length and then use `OP_CAT` to pad it to four bytes. 
A subtlety here is that negative numbers, which occur when the original hash's last byte's most significant bit is 1, 
need to be handled differently, as it would first be padded with `OP_LEFT (0x80)` and then `OP_PUSHBYTES_0 (0x00)`.

```
OP_IF
OP_PUSHBYTES_1 OP_PUSHBYTES_0
OP_ELSE
OP_PUSHBYTES_1 OP_LEFT
OP_ENDIF
```

Note that `OP_PUSHBYTES_0` and `OP_LEFT` here are not opcodes but rather data that `OP_PUSHBYTES_1` will push to the stack. 
One cannot directly write `0x00` and `0x80` in the interpreter, as they would become an empty string and `0x80 0x00`, 
respectively. 

It first uses `OP_CAT` to combine the hint elements together and compare it with the hash that is to be extracted from. 

Each of the hint number, after peeling off the sign bit, becomes a non-negative 31-bit number, ranging from 0 to 2^31 - 1. 
However, in the rest of the computation, we want the number to be below 2^31 - 1. This is done by subtracting one from the 
resulting number unless the resulting number is zero.
```
OP_DUP OP_NOT 
OP_NOTIF OP_1SUB OP_ENDIF
```

After such adjustment, one obtains an element. 

---

### Proof of Work

The Proof-of-Work check accepts two inputs: `channel` and `nonce`, and checks whether the new channel state `channel'=sha256(channel||nonce)` has sufficiently many security bits, namely, `n_bits`.

Since we don't have `OP_SUBSTR`, the check also requires hints that change depending on whether `n_bis` is divisible by 8 or not. 

If `n_bits % 8==0`, there is a single hint `suffix`, and the script checks that
```
0^(n_bits//8)||suffix==channel'
``` 

If `n_bits % 8!=0`, together with `suffix`, there is an additional byte-sized hint `msb`. Consequently, the script checks that
```
0^(n_bits//8)||msb||suffix==channel'
``` 
and also that `msb` starts with `n_bits % 8` (which would be at least 1) zero bits.


---

### License and contributors

This repository is intended to be public good. It is under the MIT license. 

A portion of the code is contributed by [L2 Iterative (L2IV)](https://www.l2iterative.com/), a crypto 
VC based in San Francisco and Hong Kong. The work receives support from Starkware, who is a limited partner in L2IV. For 
disclosure, L2IV has also invested into numerous companies active in the Bitcoin ecosystem, but this work is open-source 
and nonprofit, and is not intended for competition. The code is not investment advice.

Starkware contribtues a portion of the code, including the original Rust FRI implementation (from stwo) and some Bitcoin scripts.

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
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->
