## Circle STARK Verifier in Bitcoin Script

This repository includes Bitcoin script implementations of various cryptographic primitives for STARK.

- **M31, CM31, QM31, Circle Point** 
  * implementation of add, sub, mul of Mersenne-31 (M31) and its complex extension (CM31) and its degree-4 extension (QM31), 
    which is imported from [BitVM/rust-bitcoin-m31-or-babybear](https://github.com/BitVM/rust-bitcoin-m31-or-babybear).
  * implementation of add, sub, mul of circle points, which are over the circle curve `x^2 + y^2 = 1`.
- **Fiat-Shamir Transcript**
  * aka "channel", which is the name used in Starkware's [stwo](https://github.com/starkware-libs/stwo) library.
  * absorbing commitments and QM31 elements through `OP_CAT + OP_SHA256`.
  * squeezing random elements for Fiat-Shamir transform using hints and `OP_CAT + OP_SHA256`.
- **Merkle Tree**
  * implementation of Merkle path verification using hints and `OP_CAT + OP_SHA256`.

The next step is to implement the FRI protocol, which reasons about the degree of a quotient polynomial.

---

### Channel

The channel is used for Fiat-Shamir transform. It absorbs elements that are either prior knowledge of the verifier or provers' 
messages, and it can be squeezed to produce pseudorandom elements. There are five operations.

- `new(IV) -> channel`: initialize a new channel using an initialization vector (IV)
  * `channel := IV`
- `absorb(channel, commitment) -> channel'`: update the channel with a commitment
  * `channel' := SHA256(channel || commitment)`
- `absorb(channel, qm31) -> channel'`: update the channel with a QM31 element
  * `channel' := SHA256(channel || commit(qm31))`
- `squeeze(channel) -> (qm31, channel')`: squeeze a QM31 element out of the channel
  * `hash := SHA256(channel || 0x00)`
  * `channel' := SHA256(channel)`
  * `qm31 := extract(hash)`
- `squeeze(channel, logn) -> (q1, q2, q3, q4, q5, channel')`: squeeze five positions on a list of 2^logn elements
  * `hash := SHA256(channel || 0x00)`
  * `channel' := SHA256(channel)`
  * `q1, q2, q3, q4, q5 := extract(hash, logn)`

The constructions of commit and extract are discussed later.

---

### Commit

With `OP_CAT + OP_SHA256`, we can commit M31, CM31, and QM31 elements with a few bytes.

M31 requires only 1 byte: `commit(m31) := SHA256(m31)`.
```
OP_SHA256
```

CM31 requires 3 bytes: `commit(cm31) := SHA256(cm31.0 || SHA256(cm31.1)) `
```
OP_SHA256 OP_CAT OP_SHA256
```

QM31 requires 7 bytes: `commit(qm31) := SHA256(qm31.0.0 || SHA256(qm31.0.1 || SHA256(qm31.1.0 || SHA256(qm31.1.1))))`
```
OP_SHA256 OP_CAT OP_SHA256 OP_CAT OP_SHA256 OP_CAT OP_SHA256
```

We feel that this is the optimal.

---

### Extract

Since we do not have `OP_SUBSTR`, to extract a QM31 element or five positions from the hash, we need to use hints. The 
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

### License

This repository is intended to be public good. It is under the MIT license. 

We want to credit that the Rust FRI implementation code was based on code shared by Starkware. 