# Verifier cost under native 64-bit `OP_MUL` / `OP_MOD`

Research note (branch `research/op-mulmod`). Estimates how much the compiled
Circle-Plonk verifier's Bitcoin Script would shrink if Bitcoin gained two
hypothetical native 64-bit opcodes — `A B OP_MUL` (push `A*B`) and
`A B OP_MOD` (push `A%B`) — replacing the current 8-bit lookup-table field
multiplication.

## Headline

Total compiled script across all 72 Plonk verifier parts:

| Model | Bytes | % of baseline |
|---|---|---|
| **Baseline** — no special opcodes, 8-bit table mul | 3,310,793 | 100.0% |
| **`op-mulmod`** — native 64-bit `OP_MUL` / `OP_MOD` | 413,766 | 12.5% |
| *`free-mul` v2* — idealized floor, entire field-mul free | 229,316 | 6.9% |

**Native 64-bit mulmod cuts the verifier to ~12.5% of baseline — an ~8×
shrink, ~2.9 MB (87.5%) saved.** It reaches ~80% of the way to the theoretical
"free multiplication" floor; the remaining ~5.6 pp is stack-plumbing tax from
emulating CM31/QM31 over M31, not the multiplications themselves.

## What the `op-mulmod` model assumes

- **M31 mul** → `OP_MUL <p> OP_MOD` (`p = 2^31 − 1`).
- **`M31::inverse`** → hinted value verified by a single such mul.
- **CM31 / QM31 muls** → emulated as Karatsuba over M31 (3 / 9 M31 muls plus
  the add/sub combination).
- The **8-bit lookup-table push is dropped** entirely — no gadget reads it.
- When both `op-mulmod` and `free-mul` are enabled (e.g. `--all-features`),
  the build defers to `free-mul` so the two research models never collide.

Resulting opcode counts: **4,197 `OP_MUL` + 4,197 `OP_MOD`** (one MOD per M31
mul). Hash work (`OP_SHA256` + `OP_CAT`) is **17,807 B, unchanged across all
three models** — multiplication opcodes don't touch the LDM / Merkle / channel
path.

## Why `op-mulmod` (12.5%) doesn't reach the `free-mul` floor (6.9%)

The ~184 KB gap is plumbing, not arithmetic. `op-mulmod` composes each
extension-field mul from many small M31 ops, and every one pays real DSL
`pick`/`roll` overhead; `free-mul` v2 instead fuses each *entire* field-mul
into a single zero-byte gadget. Of the gap:

- **~83 KB** — `{distance}` number-pushes for the extra `OP_PICK` / `OP_ROLL`s,
- **~21 KB** — the `<p>` modulus pushes,
- remainder — the small M31-op plumbing itself (the pick/roll opcodes, the
  8,394 B of `OP_MUL`/`OP_MOD`, and the Karatsuba add/sub combination).

## Caveats

These are **compile-only** models. The scripts are never executed
(`OP_MUL` / `OP_MOD` are disabled in the interpreter), so the byte counts and
opcode histograms are exact but runtime is not exercised. Value-level
correctness of the mulmod construction is checked separately by the
`verify_mulmod` binary.

## Reproduce

```sh
# Totals + opcode histogram for each model:
cargo run --bin measure_categories                      # baseline
cargo run --bin measure_categories --features op-mulmod  # native mulmod
cargo run --bin measure_categories --features free-mul   # idealized floor

# Value-level correctness of the mulmod construction:
cargo run --bin verify_mulmod
```

Other measurement binaries: `measure_parts` (per-part script length),
`measure_composite` (end-to-end M31/CM31/QM31 mul cost), `measure_sizes` (raw
gadget sizes), `measure_ldm` (LDM-per-op). All compile only; they do not
execute the scripts.
