use object::write::{Object, StandardSegment, Symbol, SymbolSection, SymbolScope, SymbolKind, Relocation};
use object::{Architecture, BinaryFormat, Endianness, SectionKind, RelocationEncoding, RelocationKind, RelocationFlags};

use std::collections::HashMap;

use orgntr_ocir::ir::{OModule, OInst};
use crate::trust::TrustRecord;

// Minimal x86_64 machine encoder for Stage I (linear OCIR stream)
// - stack-only vreg allocation
// - boxed calls via _out ABI
// - frame size supports imm32 upgrade path

#[derive(Default)]
struct Code { b: Vec<u8> }
impl Code {
    fn pos(&self) -> u64 { self.b.len() as u64 }
    fn push(&mut self, x: u8) { self.b.push(x); }
    fn extend(&mut self, xs: &[u8]) { self.b.extend_from_slice(xs); }
    fn imm32(&mut self, v: i32) { self.extend(&(v as u32).to_le_bytes()); }
    fn imm64(&mut self, v: i64) { self.extend(&(v as u64).to_le_bytes()); }

    fn rex_w(&mut self, r: bool, b: bool) {
        let mut rex = 0x48u8;
        if r { rex |= 0x04; }
        if b { rex |= 0x01; }
        self.push(rex);
    }

    fn mov_r64_imm64(&mut self, reg: u8, imm: i64) {
        let lo = reg & 7;
        let hi = (reg >> 3) != 0;
        self.rex_w(false, hi);
        self.push(0xB8 + lo);
        self.imm64(imm);
    }

    fn mov_r64_mrbp_disp8(&mut self, reg: u8, disp8: i8) {
        let lo = reg & 7;
        let rhi = (reg >> 3) != 0;
        self.rex_w(rhi, false);
        self.push(0x8B);
        self.push(0x40 | (lo << 3) | 0x05);
        self.push(disp8 as u8);
    }

    fn mov_mrbp_disp8_r64(&mut self, disp8: i8, reg: u8) {
        let lo = reg & 7;
        let rhi = (reg >> 3) != 0;
        self.rex_w(rhi, false);
        self.push(0x89);
        self.push(0x40 | (lo << 3) | 0x05);
        self.push(disp8 as u8);
    }

    fn add_r64_mrbp_disp8(&mut self, reg: u8, disp8: i8) {
        let lo = reg & 7;
        let rhi = (reg >> 3) != 0;
        self.rex_w(rhi, false);
        self.push(0x03);
        self.push(0x40 | (lo << 3) | 0x05);
        self.push(disp8 as u8);
    }

    fn mov_m32_mrbp_disp8_imm32(&mut self, disp8: i8, imm: i32) {
        self.push(0xC7);
        self.push(0x40 | 0x05);
        self.push(disp8 as u8);
        self.imm32(imm);
    }

    fn mov_r64_r64(&mut self, dst: u8, src: u8) {
        let dst_lo = dst & 7;
        let src_lo = src & 7;
        let rhi = (src >> 3) != 0;
        let bhi = (dst >> 3) != 0;
        self.rex_w(rhi, bhi);
        self.push(0x89);
        self.push(0xC0 | (src_lo << 3) | dst_lo);
    }

    fn lea_r64_mrbp_disp8(&mut self, reg: u8, disp8: i8) {
        let lo = reg & 7;
        let rhi = (reg >> 3) != 0;
        self.rex_w(rhi, false);
        self.push(0x8D);
        self.push(0x40 | (lo << 3) | 0x05);
        self.push(disp8 as u8);
    }

    fn call_rel32_placeholder(&mut self) -> u64 {
        self.push(0xE8);
        let at = self.pos();
        self.imm32(0);
        at
    }

    fn prologue(&mut self) { self.push(0x55); self.extend(&[0x48, 0x89, 0xE5]); }

    fn sub_rsp_imm8(&mut self, imm8: u8) { self.extend(&[0x48, 0x83, 0xEC, imm8]); }

    // Upgrade: imm32 stack adjust
    fn sub_rsp_imm32(&mut self, imm32: i32) { self.extend(&[0x48, 0x81, 0xEC]); self.imm32(imm32); }

    fn add_rsp_imm8(&mut self, imm8: u8) { self.extend(&[0x48, 0x83, 0xC4, imm8]); }

    fn add_rsp_imm32(&mut self, imm32: i32) { self.extend(&[0x48, 0x81, 0xC4]); self.imm32(imm32); }

    fn epilogue(&mut self) { self.push(0x5D); self.push(0xC3); }
}

#[derive(Clone, Copy, Debug)]
enum SlotKind { I64, FardVal }

fn align16(n: usize) -> usize { (n + 15) & !15 }

#[derive(Default)]
struct Layout {
    slots: HashMap<u32, (SlotKind, i32)>, // reg -> (kind, disp32)
    frame_size: i32,
}

fn compute_layout(m: &OModule) -> Layout {
    let mut kind: HashMap<u32, SlotKind> = HashMap::new();
    for inst in &m.instructions {
        match inst {
            OInst::ImmI64 { dst, .. } => { kind.insert(*dst, SlotKind::I64); }
            OInst::ImmBool { dst, .. } => { kind.insert(*dst, SlotKind::I64); } // stored as i64 0/1 for now
            OInst::AddI64 { dst, .. } => { kind.insert(*dst, SlotKind::I64); }
            OInst::BoxInt { dst, .. } => { kind.insert(*dst, SlotKind::FardVal); }
            OInst::CallAddBoxed { dst_fval, .. } => { kind.insert(*dst_fval, SlotKind::FardVal); }
            OInst::CallMulBoxed { dst_fval, .. } => { kind.insert(*dst_fval, SlotKind::FardVal); }
            _ => {}
        }
    }

    let mut regs: Vec<u32> = kind.keys().copied().collect();
    regs.sort_unstable();

    let mut off: i32 = 0;
    let mut slots: HashMap<u32, (SlotKind, i32)> = HashMap::new();
    for r in regs {
        let k = kind[&r];
        let sz = match k { SlotKind::I64 => 8, SlotKind::FardVal => 16 };
        off += sz;
        slots.insert(r, (k, -off));
    }

    let framed = align16(off as usize) as i32;
    Layout { slots, frame_size: framed }
}

fn disp(layout: &Layout, reg: u32) -> i32 { layout.slots[&reg].1 }

// disp32 addressing is not yet implemented in Stage I encoder.
// We keep Stage I using disp8, but the layout is computed in i32 so upgrading is mechanical.
// For now, enforce disp8 compatibility:
fn disp8(layout: &Layout, reg: u32) -> i8 {
    let d = disp(layout, reg);
    if d < -128 || d > 127 {
        panic!("Stage I disp8 overflow (need disp32 encoder): {}", d);
    }
    d as i8
}

fn fval_tag_disp(base: i8) -> i8 { base }
fn fval_pad_disp(base: i8) -> i8 { base + 4 }
fn fval_pay_disp(base: i8) -> i8 { base + 8 }

pub fn emit_object_x86_64_sysv_stage1(m: &OModule, trust: &TrustRecord) -> Vec<u8> {
    assert_eq!(m.entry_name, "fard_main");
    let layout = compute_layout(m);

    let mut code = Code::default();
    code.prologue();

    // Stack adjust: choose imm8 vs imm32 deterministically.
    if layout.frame_size != 0 {
        if layout.frame_size < 128 {
            code.sub_rsp_imm8(layout.frame_size as u8);
        } else {
            code.sub_rsp_imm32(layout.frame_size);
        }
    }

    struct PendingCall { at: u64, sym: &'static [u8] }
    let mut pending: Vec<PendingCall> = vec![];

    for inst in &m.instructions {
        match *inst {
            OInst::ImmI64 { dst, val } => {
                code.mov_r64_imm64(0, val);
                let d = disp8(&layout, dst);
                code.mov_mrbp_disp8_r64(d, 0);
            }

            OInst::AddI64 { dst, lhs, rhs } => {
                let dl = disp8(&layout, lhs);
                let dr = disp8(&layout, rhs);
                code.mov_r64_mrbp_disp8(0, dl);
                code.add_r64_mrbp_disp8(0, dr);
                let dd = disp8(&layout, dst);
                code.mov_mrbp_disp8_r64(dd, 0);
            }

            OInst::BoxInt { dst, src_i64 } => {
                let base = disp8(&layout, dst);
                code.mov_m32_mrbp_disp8_imm32(fval_tag_disp(base), 0);
                code.mov_m32_mrbp_disp8_imm32(fval_pad_disp(base), 0);
                let si = disp8(&layout, src_i64);
                code.mov_r64_mrbp_disp8(0, si);
                code.mov_mrbp_disp8_r64(fval_pay_disp(base), 0);
            }

            OInst::CallAddBoxed { dst_fval, lhs_fval, rhs_fval } => {
                emit_call_boxed_2(&mut code, &layout, dst_fval, lhs_fval, rhs_fval);
                let at = code.call_rel32_placeholder();
                pending.push(PendingCall { at, sym: b"fard_add_boxed_out" });
            }

            OInst::CallMulBoxed { dst_fval, lhs_fval, rhs_fval } => {
                emit_call_boxed_2(&mut code, &layout, dst_fval, lhs_fval, rhs_fval);
                let at = code.call_rel32_placeholder();
                pending.push(PendingCall { at, sym: b"fard_mul_boxed_out" });
            }

            OInst::RetI64 { src } => {
                let d = disp8(&layout, src);
                code.mov_r64_mrbp_disp8(0, d);
                // early return: tear down frame + ret
                if layout.frame_size != 0 {
                    if layout.frame_size < 128 { code.add_rsp_imm8(layout.frame_size as u8); }
                    else { code.add_rsp_imm32(layout.frame_size); }
                }
                code.epilogue();
                // Stage I: ignore further instructions after RetI64 in emitter
                break;
            }

            // Stage II+ instructions are rejected by stage1 emitter:
            _ => panic!("Stage I emitter does not support {:?}", inst),
        }
    }

    // If no RetI64 emitted, return last i64 reg if any, else 0.
    if !code.b.ends_with(&[0x5D, 0xC3]) {
        let mut ret: Option<u32> = None;
        for inst in m.instructions.iter().rev() {
            match inst {
                OInst::ImmI64 { dst, .. } => { ret = Some(*dst); break; }
                OInst::AddI64 { dst, .. } => { ret = Some(*dst); break; }
                _ => {}
            }
        }
        if let Some(r) = ret {
            let d = disp8(&layout, r);
            code.mov_r64_mrbp_disp8(0, d);
        } else {
            code.mov_r64_imm64(0, 0);
        }
        if layout.frame_size != 0 {
            if layout.frame_size < 128 { code.add_rsp_imm8(layout.frame_size as u8); }
            else { code.add_rsp_imm32(layout.frame_size); }
        }
        code.epilogue();
    }

    let format = if cfg!(target_os = "macos") { BinaryFormat::MachO } else { BinaryFormat::Elf };
    let mut obj = Object::new(format, Architecture::X86_64, Endianness::Little);

    let text_id = obj.add_section(
        obj.segment_name(StandardSegment::Text).to_vec(),
        b".text".to_vec(),
        SectionKind::Text,
    );
    obj.append_section_data(text_id, &code.b, 16);

    obj.add_symbol(Symbol {
        name: b"fard_main".to_vec(),
        value: 0,
        size: code.b.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text_id),
        flags: object::SymbolFlags::None,
    });

    // undefined runtime symbols + relocations
    let mut sym_cache: HashMap<&'static [u8], object::write::SymbolId> = HashMap::new();
    for p in &pending {
        let sid = *sym_cache.entry(p.sym).or_insert_with(|| {
            obj.add_symbol(Symbol {
                name: p.sym.to_vec(),
                value: 0,
                size: 0,
                kind: SymbolKind::Text,
                scope: SymbolScope::Unknown,
                weak: false,
                section: SymbolSection::Undefined,
                flags: object::SymbolFlags::None,
            })
        });

        obj.add_relocation(
            text_id,
            Relocation { offset: p.at, symbol: sid, addend: -4, flags: RelocationFlags::Generic { kind: RelocationKind::Relative, encoding: RelocationEncoding::Generic, size: 32 } },
        ).expect("reloc");
    }

    let trust_bytes = trust.to_json_bytes();
    let trust_id = obj.add_section(
        obj.segment_name(StandardSegment::Data).to_vec(),
        b".fard.trust".to_vec(),
        SectionKind::ReadOnlyData,
    );
    obj.append_section_data(trust_id, &trust_bytes, 1);

    obj.add_symbol(Symbol {
        name: b"__fard_trust".to_vec(),
        value: 0,
        size: trust_bytes.len() as u64,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(trust_id),
        flags: object::SymbolFlags::None,
    });

    obj.write().expect("write object")
}

fn emit_call_boxed_2(code: &mut Code, layout: &Layout, dst_fval: u32, lhs_fval: u32, rhs_fval: u32) {
    // rdi = &out
    // rsi = a.tagpad (u64)
    // rdx = a.payload
    // rcx = b.tagpad (u64)
    // r8  = b.payload

    let out_base = disp8(layout, dst_fval);
    let a_base = disp8(layout, lhs_fval);
    let b_base = disp8(layout, rhs_fval);

    code.lea_r64_mrbp_disp8(7, out_base);              // rdi
    code.mov_r64_mrbp_disp8(6, fval_tag_disp(a_base)); // rsi
    code.mov_r64_mrbp_disp8(2, fval_pay_disp(a_base)); // rdx
    code.mov_r64_mrbp_disp8(1, fval_tag_disp(b_base)); // rcx

    code.mov_r64_mrbp_disp8(0, fval_pay_disp(b_base)); // rax
    code.mov_r64_r64(8, 0);                             // r8 = rax
}
