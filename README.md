# COMPILER — ORGNTR (Stage I → Deterministic Upgrades Roadmap)

This repository is a **drop-in, compiler-backend engineering scaffold** for ORGNTR: an LLVM replacement grounded in:
- ASC7 certified source (W*),
- SEMBIT specialization decisions,
- OCIR as the semantic truth source,
- x86_64 SysV object emission without LLVM.

This zip is intended to be opened directly in VS Code.

---

## Current State (Included in this zip)

### Included crates
- `crates/orgntr_rt`  
  Execution boundary. Provides `_out` (sret-style) boxed arithmetic functions:
  - `fard_add_boxed_out(out, a, b)`
  - `fard_mul_boxed_out(out, a, b)`
  ABI is frozen to `FardVal { u32 tag, u32 pad, u64 payload }`.

- `crates/orgntr_ocir`  
  ORGNTR Core IR (OCIR): the **truth source**.
  - IR in `src/ir.rs`
  - verifier in `src/verifier.rs`
  - canonical `ocir_hash` = `sha256(bincode(instructions))`

- `crates/orgntr_target_x86_64`  
  Stage I x86_64 SysV backend.
  - emits a `.o` file with symbol `fard_main`
  - emits `.fard.trust` read-only section containing JSON trust payload
  - emits `call rel32` relocations to runtime functions

- `crates/orgntr_cli`  
  Minimal driver producing `out.o` from an OCIR module.

---

## Build & Run (Stage I)

### 1) Build object
```bash
cargo run -p orgntr_cli
```

This writes:
- `out.o`

### 2) Link with runtime
You must link `out.o` with the `orgntr_rt` staticlib plus a tiny host stub that calls `fard_main`.

Create `host.c` in repo root:

```c
#include <stdint.h>
#include <stdio.h>

int64_t fard_main(void);

int main() {
  int64_t r = fard_main();
  printf("%lld\n", (long long)r);
  return 0;
}
```

Then build runtime and link:

**macOS (clang):**
```bash
cargo build -p orgntr_rt
clang -o out host.c out.o target/debug/liborgntr_rt.a
./out
```

**Linux (clang):**
```bash
cargo build -p orgntr_rt
clang -o out host.c out.o target/debug/liborgntr_rt.a -ldl -lpthread
./out
```

Expected output (demo program): `42`

---

## Deterministic Upgrades (Your requested next steps)

The current backend is Stage I: **linear OCIR stream** (no control flow), stack-only vregs, disp8-only addressing.

Your next deterministic upgrades are:

1) multi-block OCIR + labels  
2) conditional branches  
3) frame size imm32  
4) more calls and relocations  
5) a real OMIR layer (regalloc, scheduling)

Below is the exact implementation map (file-level, no ambiguity).

---

# Upgrade 1 — Multi-block OCIR + labels

## Goal
Replace “linear instructions” with:
- blocks
- labels
- terminators
- SSA discipline (phis later)

## OCIR changes
**File:** `crates/orgntr_ocir/src/ir.rs`

Replace:
- `OModule { instructions: Vec<OInst> }`

With:
- `OModule { funcs: Vec<OFunc> }`
- `OFunc { blocks: Vec<OBlock> }`
- `OBlock { label: u32, insts: Vec<OInst>, term: OTerm }`

Minimal forms:

```rust
pub struct OFunc {
  pub name: String,
  pub blocks: Vec<OBlock>,
}
pub struct OBlock {
  pub label: u32,
  pub insts: Vec<OInst>,
  pub term: OTerm,
}
pub enum OTerm {
  RetI64 { src: u32 },
  Br { to: u32 },
  BrCond { cond: u32, t: u32, f: u32 },
}
```

## Verifier changes
**File:** `crates/orgntr_ocir/src/verifier.rs`

Add checks:
- all block labels unique
- every branch target label exists
- every block ends in exactly one terminator
- no instructions after terminator inside a block

---

# Upgrade 2 — Conditional branches

## Goal
Emit `cmp` + `jne/jmp` sequences and fixup relocations to labels.

## Backend changes
**File:** `crates/orgntr_target_x86_64/src/emit.rs`

Add:
- label address map: `label -> text_offset`
- forward fixups list: patches for `jmp rel32` and `jcc rel32`
- emit:
  - `cmp reg/mem, 0`
  - `jne rel32` (or `je`)
  - `jmp rel32`

Instruction encodings (x86_64):
- `cmp r/m64, imm8`: `48 83 7D disp8 00`  (cmp qword [rbp+disp], 0)
- `jne rel32`: `0F 85 xx xx xx xx`
- `jmp rel32`: `E9 xx xx xx xx`

---

# Upgrade 3 — Frame size imm32 + disp32 addressing

Stage I already includes `sub rsp, imm32` and `add rsp, imm32` helpers.

## Required next change
Implement disp32 memory forms when stack grows beyond disp8.

**File:** `crates/orgntr_target_x86_64/src/emit.rs`

Add functions:
- `mov r64, [rbp + disp32]`  (ModRM mod=10 with disp32)
- `mov [rbp + disp32], r64`
- `lea r64, [rbp + disp32]`

ModRM rules:
- mod=10 indicates disp32 follows.
- rm=101 with mod!=00 is rbp (ok).

---

# Upgrade 4 — More calls and relocations

Stage I supports `call rel32` with a relocation to an undefined symbol.

Extend:
- more runtime calls (mul, cmp, bool ops)
- imports to `orgntr_rt` expanded surface

**File:** `crates/orgntr_target_x86_64/src/emit.rs`
- extend pending relocations table to multiple symbols (already done)

---

# Upgrade 5 — Real OMIR layer (regalloc, scheduling)

## Why
Stack-only vregs are deterministic but slow and block register-based control flow.

## OMIR introduction
Create crate:

```
crates/orgntr_omir/
  src/lib.rs
  src/ir.rs
  src/regalloc.rs
  src/schedule.rs
```

### OMIR minimal IR
- explicit virtual registers
- explicit moves
- explicit call clobbers
- explicit stack slots
- explicit blocks

### Deterministic regalloc (Stage II)
- linear scan allocator (deterministic)
- fixed ordering: blocks in source order, instrs in order
- tie-breaking: lowest vreg id wins

### Scheduling (Stage II)
- do nothing first (preserve OCIR order)
- later: local peephole + move coalescing (deterministic)

## Backend pivot
Backend becomes:
- OCIR → OMIR lowering
- OMIR → machine bytes

---

## Repo Structure Summary

```
crates/
  orgntr_rt/
  orgntr_ocir/
  orgntr_target_x86_64/
  orgntr_cli/
```

---

## Stage I Known Limitations

- The x86 emitter currently rejects control-flow instructions at runtime (`panic!`) in Stage I mode.
- Bool values are stored as i64 0/1 in the emitter (upgrade when adding `BrCond`).
- Canonical trust JSON is not yet the ValueCore canonical JSON; replace `TrustRecord::to_json_bytes()` with your canonical encoder when ready.

---

## Next Work Items (Direct edits)

If you want to begin Upgrade 1 immediately, start here:

1) `crates/orgntr_ocir/src/ir.rs`
   - replace linear `instructions` with blocks/terminators

2) `crates/orgntr_ocir/src/verifier.rs`
   - add CFG validity checks

3) `crates/orgntr_target_x86_64/src/emit.rs`
   - change emitter to:
     - emit blocks
     - compute label offsets
     - patch rel32 jumps

Everything else can remain unchanged during the first CFG step.

