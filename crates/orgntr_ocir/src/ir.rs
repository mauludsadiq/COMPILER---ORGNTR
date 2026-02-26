use sha2::{Sha256, Digest};
use serde::Serialize;

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OType { I64, Bool, FardVal }

#[derive(Serialize, Debug, Clone)]
pub enum OInst {
    // Values
    ImmI64 { dst: u32, val: i64 },
    ImmBool { dst: u32, val: bool },

    // Arithmetic
    AddI64 { dst: u32, lhs: u32, rhs: u32 },

    // Boxing / boundary
    BoxInt { dst: u32, src_i64: u32 },

    // Calls (Stage I)
    // Uses the _out ABI: dst_fval is a stack slot where callee writes.
    CallAddBoxed { dst_fval: u32, lhs_fval: u32, rhs_fval: u32 },
    CallMulBoxed { dst_fval: u32, lhs_fval: u32, rhs_fval: u32 },

    // ========= Upgrades (Stage II+) =========
    // Multi-block control flow (labels are block ids)
    Label { block: u32 },

    // Conditional branch on Bool register
    BrCond { cond: u32, then_block: u32, else_block: u32 },

    // Unconditional branch
    Br { to_block: u32 },

    // Return i64 (Stage I: return i64 only)
    RetI64 { src: u32 },
}

#[derive(Serialize, Debug)]
pub struct OModule {
    pub instructions: Vec<OInst>,
    pub entry_name: String, // "fard_main"
}

impl OModule {
    /// OCIR hash: canonical serialization of the IR stream.
    /// Stage I uses bincode on the instruction vector.
    pub fn compute_hash_hex(&self) -> String {
        let bytes = bincode::serialize(&self.instructions).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        hex::encode(hasher.finalize())
    }
}
