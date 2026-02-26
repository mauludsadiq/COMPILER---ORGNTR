use crate::ir::{OModule, OInst, OType};
use std::collections::HashMap;

pub fn verify(module: &OModule) -> Result<(), String> {
    // Type environment: virtual register -> OType
    let mut reg_types: HashMap<u32, OType> = HashMap::new();

    // Block inventory for Stage II+ checks
    let mut seen_label: HashMap<u32, usize> = HashMap::new();
    for (i, inst) in module.instructions.iter().enumerate() {
        if let OInst::Label { block } = inst {
            if seen_label.insert(*block, i).is_some() {
                return Err(format!("Duplicate label for block {}", block));
            }
        }
    }

    for inst in &module.instructions {
        match inst {
            OInst::ImmI64 { dst, .. } => { reg_types.insert(*dst, OType::I64); }
            OInst::ImmBool { dst, .. } => { reg_types.insert(*dst, OType::Bool); }

            OInst::AddI64 { dst, lhs, rhs } => {
                if reg_types.get(lhs) != Some(&OType::I64) || reg_types.get(rhs) != Some(&OType::I64) {
                    return Err(format!("AddI64 requires I64 inputs at dst {}", dst));
                }
                reg_types.insert(*dst, OType::I64);
            }

            OInst::BoxInt { dst, src_i64 } => {
                if reg_types.get(src_i64) != Some(&OType::I64) {
                    return Err(format!("BoxInt requires I64 input at dst {}", dst));
                }
                reg_types.insert(*dst, OType::FardVal);
            }

            OInst::CallAddBoxed { dst_fval, lhs_fval, rhs_fval } |
            OInst::CallMulBoxed { dst_fval, lhs_fval, rhs_fval } => {
                if reg_types.get(lhs_fval) != Some(&OType::FardVal) || reg_types.get(rhs_fval) != Some(&OType::FardVal) {
                    return Err(format!("Boxed call requires FardVal inputs at dst {}", dst_fval));
                }
                reg_types.insert(*dst_fval, OType::FardVal);
            }

            // Stage II+: control-flow invariants (lightweight now; deepen later)
            OInst::Label { .. } => { /* ok */ }

            OInst::BrCond { cond, then_block, else_block } => {
                if reg_types.get(cond) != Some(&OType::Bool) {
                    return Err(format!("BrCond requires Bool cond reg {}", cond));
                }
                if !seen_label.contains_key(then_block) || !seen_label.contains_key(else_block) {
                    return Err(format!("BrCond targets must be labeled: then={}, else={}", then_block, else_block));
                }
            }

            OInst::Br { to_block } => {
                if !seen_label.contains_key(to_block) {
                    return Err(format!("Br target must be labeled: {}", to_block));
                }
            }

            OInst::RetI64 { src } => {
                if reg_types.get(src) != Some(&OType::I64) {
                    return Err(format!("RetI64 requires I64 reg {}", src));
                }
            }
        }
    }

    Ok(())
}
