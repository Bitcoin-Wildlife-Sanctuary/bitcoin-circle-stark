
# Primitives

## M31, CM31, QM31, Circle Point

- Implementation of add, sub, mul of Mersenne-31 (M31), its complex extension (CM31), and its degree-4 extension (QM31), which is imported from [BitVM/rust-bitcoin-m31-or-babybear](https://github.com/BitVM/rust-bitcoin-m31-or-babybear).

## CirclePoint over QM31

- Implementation of doubling of a circle point over QM31.
- Implementation of drawing a random point on the circle over QM31, useful for Order-Optimal Data Structures (OODS).

## Fiat-Shamir Transcript

- Also known as "channel," which is the term used in Starkware's [stwo](https://github.com/starkware-libs/stwo) library.
- Absorbing commitments and QM31 elements through `OP_CAT + OP_SHA256`.
- Squeezing random elements for Fiat-Shamir transform using hints and `OP_CAT + OP_SHA256`.

## Proof-of-Work Check

- Calculating a proof-of-work nonce for the "channel", based on specified security bits.
- Verifying the proof-of-work nonce and computing the new "channel" state.

## Merkle Tree

- Implementation of Merkle path verification using hints and `OP_CAT + OP_SHA256`.