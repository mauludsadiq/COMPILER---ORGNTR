use object::write::{
    Object, Relocation, StandardSegment, Symbol, SymbolKind, SymbolScope, SymbolSection,
};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    SectionKind,
};

use std::collections::HashMap;

use crate::trust::TrustRecord;
use orgntr_ocir::ir::{OInst, OModule, OTerm};

#[derive(Default)]
struct Code {
    b: Vec<u8>,
}

impl Code {
    fn pos(&self) -> u64 {
        self.b.len() as u64
    }
    fn push(&mut self, x: u8) {
        self.b.push(x);
    }
    fn extend(&mut self, xs: &[u8]) {
        self.b.extend_from_slice(xs);
    }
    fn imm32(&mut self, v: i32) {
        self.extend(&(v as u32).to_le_bytes());
    }
    fn imm64(&mut self, v: i64) {
        self.extend(&(v as u64).to_le_bytes());
    }

    fn patch_i32_le(&mut self, at: u64, v: i32) {
        let at = at as usize;
        let bs = (v as u32).to_le_bytes();
        self.b[at..at + 4].copy_from_slice(&bs);
    }

    fn rex_w(&mut self, r: bool, b: bool) {
        let mut rex = 0x48u8;
        if r {
            rex |= 0x04;
        }
        if b {
            rex |= 0x01;
        }
        self.push(rex);
    }

    // prologue/epilogue
    fn prologue(&mut self) {
        self.push(0x55);
        self.extend(&[0x48, 0x89, 0xE5]);
    }
    fn epilogue(&mut self) {
        self.push(0x5D);
        self.push(0xC3);
    }

    fn sub_rsp_imm8(&mut self, imm8: u8) {
        self.extend(&[0x48, 0x83, 0xEC, imm8]);
    }
    fn sub_rsp_imm32(&mut self, imm32: i32) {
        self.extend(&[0x48, 0x81, 0xEC]);
        self.imm32(imm32);
    }
    fn add_rsp_imm8(&mut self, imm8: u8) {
        self.extend(&[0x48, 0x83, 0xC4, imm8]);
    }
    fn add_rsp_imm32(&mut self, imm32: i32) {
        self.extend(&[0x48, 0x81, 0xC4]);
        self.imm32(imm32);
    }

    // mov r64, imm64
    fn mov_r64_imm64(&mut self, reg: u8, imm: i64) {
        let lo = reg & 7;
        let hi = (reg >> 3) != 0;
        self.rex_w(false, hi);
        self.push(0xB8 + lo);
        self.imm64(imm);
    }

    // mov r64, [rbp+disp] (disp8/disp32)
    fn mov_r64_mrbp_disp(&mut self, reg: u8, disp: i32) {
        let lo = reg & 7;
        let rhi = (reg >> 3) != 0;
        self.rex_w(rhi, false);
        self.push(0x8B);
        if disp >= -128 && disp <= 127 {
            self.push(0x40 | (lo << 3) | 0x05);
            self.push(disp as i8 as u8);
        } else {
            self.push(0x80 | (lo << 3) | 0x05);
            self.imm32(disp);
        }
    }

    // mov [rbp+disp], r64 (disp8/disp32)
    fn mov_mrbp_disp_r64(&mut self, disp: i32, reg: u8) {
        let lo = reg & 7;
        let rhi = (reg >> 3) != 0;
        self.rex_w(rhi, false);
        self.push(0x89);
        if disp >= -128 && disp <= 127 {
            self.push(0x40 | (lo << 3) | 0x05);
            self.push(disp as i8 as u8);
        } else {
            self.push(0x80 | (lo << 3) | 0x05);
            self.imm32(disp);
        }
    }

    // add r64, [rbp+disp]
    fn add_r64_mrbp_disp(&mut self, reg: u8, disp: i32) {
        let lo = reg & 7;
        let rhi = (reg >> 3) != 0;
        self.rex_w(rhi, false);
        self.push(0x03);
        if disp >= -128 && disp <= 127 {
            self.push(0x40 | (lo << 3) | 0x05);
            self.push(disp as i8 as u8);
        } else {
            self.push(0x80 | (lo << 3) | 0x05);
            self.imm32(disp);
        }
    }

    // mov dword [rbp+disp], imm32
    fn mov_m32_mrbp_disp_imm32(&mut self, disp: i32, imm: i32) {
        self.push(0xC7);
        if disp >= -128 && disp <= 127 {
            self.push(0x40 | 0x05);
            self.push(disp as i8 as u8);
        } else {
            self.push(0x80 | 0x05);
            self.imm32(disp);
        }
        self.imm32(imm);
    }

    // lea r64, [rbp+disp]
    fn lea_r64_mrbp_disp(&mut self, reg: u8, disp: i32) {
        let lo = reg & 7;
        let rhi = (reg >> 3) != 0;
        self.rex_w(rhi, false);
        self.push(0x8D);
        if disp >= -128 && disp <= 127 {
            self.push(0x40 | (lo << 3) | 0x05);
            self.push(disp as i8 as u8);
        } else {
            self.push(0x80 | (lo << 3) | 0x05);
            self.imm32(disp);
        }
    }

    // mov r64, r64
    fn mov_r64_r64(&mut self, dst: u8, src: u8) {
        let dst_lo = dst & 7;
        let src_lo = src & 7;
        let rhi = (src >> 3) != 0;
        let bhi = (dst >> 3) != 0;
        self.rex_w(rhi, bhi);
        self.push(0x89);
        self.push(0xC0 | (src_lo << 3) | dst_lo);
    }

    // call rel32 placeholder
    fn call_rel32_placeholder(&mut self) -> u64 {
        self.push(0xE8);
        let at = self.pos();
        self.imm32(0);
        at
    }

    // jmp rel32 placeholder
    fn jmp_rel32_placeholder(&mut self) -> u64 {
        self.push(0xE9);
        let at = self.pos();
        self.imm32(0);
        at
    }

    // jne rel32 placeholder (0F 85)
    fn jne_rel32_placeholder(&mut self) -> u64 {
        self.extend(&[0x0F, 0x85]);
        let at = self.pos();
        self.imm32(0);
        at
    }

    // cmp qword [rbp+disp], 0 (83 /7 ib)
    fn cmp_mrbp_disp_imm8_0(&mut self, disp: i32) {
        self.extend(&[0x48, 0x83]);
        self.push(0x7D);
        if disp >= -128 && disp <= 127 {
            self.push(disp as i8 as u8);
        } else {
            // use cmp r/m64, imm32: 48 81 /7 id  (modrm for [rbp+disp32] is 0xBD)
            self.b.pop(); // remove 0x7D
            self.extend(&[0x81, 0xBD]);
            self.imm32(disp);
            self.imm32(0);
            return;
        }
        self.push(0x00);
    }
}

#[derive(Clone, Copy, Debug)]
enum SlotKind {
    I64,
    FardVal,
}

fn align16(n: usize) -> usize {
    (n + 15) & !15
}

#[derive(Default)]
struct Layout {
    slots: HashMap<u32, (SlotKind, i32)>, // reg -> (kind, disp from rbp)
    frame_size: i32,
}

fn compute_layout(m: &OModule) -> Layout {
    let mut kinds: HashMap<u32, SlotKind> = HashMap::new();

    let f = m
        .funcs
        .iter()
        .find(|f| f.name == m.entry)
        .expect("entry func");
    for b in &f.blocks {
        for inst in &b.insts {
            match inst {
                OInst::ImmI64 { dst, .. } => {
                    kinds.insert(*dst, SlotKind::I64);
                }
                OInst::ImmBool { dst, .. } => {
                    kinds.insert(*dst, SlotKind::I64);
                } // store bool as i64 0/1
                OInst::AddI64 { dst, .. } => {
                    kinds.insert(*dst, SlotKind::I64);
                }
                OInst::BoxInt { dst, .. } => {
                    kinds.insert(*dst, SlotKind::FardVal);
                }
                OInst::CallAddBoxed { dst_fval, .. } => {
                    kinds.insert(*dst_fval, SlotKind::FardVal);
                }
                OInst::CallMulBoxed { dst_fval, .. } => {
                    kinds.insert(*dst_fval, SlotKind::FardVal);
                }
            }
        }
        match &b.term {
            OTerm::RetI64 { .. } => {}
            OTerm::Br { .. } => {}
            OTerm::BrCond { cond, .. } => {
                kinds.entry(*cond).or_insert(SlotKind::I64);
            }
        }
    }

    let mut regs: Vec<u32> = kinds.keys().copied().collect();
    regs.sort_unstable();

    let mut off: i32 = 0;
    let mut slots: HashMap<u32, (SlotKind, i32)> = HashMap::new();
    for r in regs {
        let k = kinds[&r];
        let sz = match k {
            SlotKind::I64 => 8,
            SlotKind::FardVal => 16,
        };
        off += sz;
        slots.insert(r, (k, -off));
    }

    let framed = align16(off as usize) as i32;
    Layout {
        slots,
        frame_size: framed,
    }
}

fn disp(layout: &Layout, reg: u32) -> i32 {
    layout.slots[&reg].1
}

fn fval_tag_disp(base: i32) -> i32 {
    base
}
fn fval_pad_disp(base: i32) -> i32 {
    base + 4
}
fn fval_pay_disp(base: i32) -> i32 {
    base + 8
}

struct PendingCall {
    at: u64,
    sym: &'static [u8],
}
struct PendingJmp {
    at: u64,
    target_label: u32,
}
struct PendingJne {
    at: u64,
    target_label: u32,
}

pub fn emit_object_x86_64_sysv_stage1(m: &OModule, trust: &TrustRecord) -> Vec<u8> {
    let layout = compute_layout(m);
    let f = m
        .funcs
        .iter()
        .find(|f| f.name == m.entry)
        .expect("entry func");

    let mut code = Code::default();
    code.prologue();

    if layout.frame_size != 0 {
        if layout.frame_size < 128 {
            code.sub_rsp_imm8(layout.frame_size as u8);
        } else {
            code.sub_rsp_imm32(layout.frame_size);
        }
    }

    let mut label_off: HashMap<u32, u64> = HashMap::new();
    let mut pending_calls: Vec<PendingCall> = vec![];
    let mut pending_jmps: Vec<PendingJmp> = vec![];
    let mut pending_jnes: Vec<PendingJne> = vec![];

    for b in &f.blocks {
        label_off.insert(b.label, code.pos());

        for inst in &b.insts {
            match inst {
                OInst::ImmI64 { dst, val } => {
                    code.mov_r64_imm64(0, *val);
                    let d = disp(&layout, *dst);
                    code.mov_mrbp_disp_r64(d, 0);
                }

                OInst::ImmBool { dst, val } => {
                    let v = if *val { 1i64 } else { 0i64 };
                    code.mov_r64_imm64(0, v);
                    let d = disp(&layout, *dst);
                    code.mov_mrbp_disp_r64(d, 0);
                }

                OInst::AddI64 { dst, lhs, rhs } => {
                    let dl = disp(&layout, *lhs);
                    let dr = disp(&layout, *rhs);
                    code.mov_r64_mrbp_disp(0, dl);
                    code.add_r64_mrbp_disp(0, dr);
                    let dd = disp(&layout, *dst);
                    code.mov_mrbp_disp_r64(dd, 0);
                }

                OInst::BoxInt { dst, src_i64 } => {
                    let base = disp(&layout, *dst);
                    code.mov_m32_mrbp_disp_imm32(fval_tag_disp(base), 0);
                    code.mov_m32_mrbp_disp_imm32(fval_pad_disp(base), 0);
                    let si = disp(&layout, *src_i64);
                    code.mov_r64_mrbp_disp(0, si);
                    code.mov_mrbp_disp_r64(fval_pay_disp(base), 0);
                }

                OInst::CallAddBoxed {
                    dst_fval,
                    lhs_fval,
                    rhs_fval,
                } => {
                    emit_call_boxed_2(&mut code, &layout, *dst_fval, *lhs_fval, *rhs_fval);
                    let at = code.call_rel32_placeholder();
                    pending_calls.push(PendingCall {
                        at,
                        sym: b"fard_add_boxed_out",
                    });
                }

                OInst::CallMulBoxed {
                    dst_fval,
                    lhs_fval,
                    rhs_fval,
                } => {
                    emit_call_boxed_2(&mut code, &layout, *dst_fval, *lhs_fval, *rhs_fval);
                    let at = code.call_rel32_placeholder();
                    pending_calls.push(PendingCall {
                        at,
                        sym: b"fard_mul_boxed_out",
                    });
                }
            }
        }

        match &b.term {
            OTerm::RetI64 { src } => {
                let d = disp(&layout, *src);
                code.mov_r64_mrbp_disp(0, d);
                if layout.frame_size != 0 {
                    if layout.frame_size < 128 {
                        code.add_rsp_imm8(layout.frame_size as u8);
                    } else {
                        code.add_rsp_imm32(layout.frame_size);
                    }
                }
                code.epilogue();
            }

            OTerm::Br { to } => {
                let at = code.jmp_rel32_placeholder();
                pending_jmps.push(PendingJmp {
                    at,
                    target_label: *to,
                });
            }

            OTerm::BrCond {
                cond,
                then_blk,
                else_blk,
            } => {
                let cdisp = disp(&layout, *cond);
                code.cmp_mrbp_disp_imm8_0(cdisp);

                let at_jne = code.jne_rel32_placeholder();
                pending_jnes.push(PendingJne {
                    at: at_jne,
                    target_label: *then_blk,
                });

                let at_jmp = code.jmp_rel32_placeholder();
                pending_jmps.push(PendingJmp {
                    at: at_jmp,
                    target_label: *else_blk,
                });
            }
        }
    }

    // Patch branch fixups (rel32 = target - next_ip)
    for pj in &pending_jmps {
        let tgt = *label_off.get(&pj.target_label).expect("label missing");
        let next_ip = pj.at + 4;
        let rel = (tgt as i64) - (next_ip as i64);
        code.patch_i32_le(pj.at, rel as i32);
    }
    for pn in &pending_jnes {
        let tgt = *label_off.get(&pn.target_label).expect("label missing");
        let next_ip = pn.at + 4;
        let rel = (tgt as i64) - (next_ip as i64);
        code.patch_i32_le(pn.at, rel as i32);
    }

    // Object file build
    let format = BinaryFormat::MachO;
    let mut obj = Object::new(format, Architecture::X86_64, Endianness::Little);

    // Emit LC_BUILD_VERSION so ld64 does not warn "no platform load command found".
    // Encoding is (major<<16) | (minor<<8) | patch.
    let mut bv = object::write::MachOBuildVersion::default();
    bv.platform = object::macho::PLATFORM_MACOS;
    bv.minos = (11u32 << 16) | (0u32 << 8) | 0u32;
    bv.sdk = (13u32 << 16) | (0u32 << 8) | 0u32;
    obj.set_macho_build_version(bv);

    // Emit LC_BUILD_VERSION so ld64 does not warn "no platform load command found".
    // Encoding is (major<<16) | (minor<<8) | patch.
    let mut bv = object::write::MachOBuildVersion::default();
    bv.platform = object::macho::PLATFORM_MACOS;
    bv.minos = (11u32 << 16) | (0u32 << 8) | 0u32;
    bv.sdk = (13u32 << 16) | (0u32 << 8) | 0u32;
    obj.set_macho_build_version(bv);

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

    // Undefined runtime symbols + relocations for calls
    let mut sym_cache: HashMap<&'static [u8], object::write::SymbolId> = HashMap::new();

    for p in &pending_calls {
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
            Relocation {
                offset: p.at,
                symbol: sid,
                addend: -4,
                flags: RelocationFlags::Generic {
                    kind: RelocationKind::Relative,
                    encoding: RelocationEncoding::Generic,
                    size: 32,
                },
            },
        )
        .expect("reloc");
    }

    // Trust section
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

fn emit_call_boxed_2(
    code: &mut Code,
    layout: &Layout,
    dst_fval: u32,
    lhs_fval: u32,
    rhs_fval: u32,
) {
    // SysV args:
    // rdi = &out
    // rsi = a.tagpad (u64)   (we load starting at tag)
    // rdx = a.payload (u64)
    // rcx = b.tagpad (u64)
    // r8  = b.payload (u64)

    let out_base = disp(layout, dst_fval);
    let a_base = disp(layout, lhs_fval);
    let b_base = disp(layout, rhs_fval);

    // lea rdi, [rbp+out]
    code.lea_r64_mrbp_disp(7, out_base);

    // rsi = *(u64*)&a.tag (load from tag disp)
    code.mov_r64_mrbp_disp(6, fval_tag_disp(a_base));

    // rdx = a.payload
    code.mov_r64_mrbp_disp(2, fval_pay_disp(a_base));

    // rcx = *(u64*)&b.tag
    code.mov_r64_mrbp_disp(1, fval_tag_disp(b_base));

    // r8 = b.payload (via rax then move)
    code.mov_r64_mrbp_disp(0, fval_pay_disp(b_base));
    code.mov_r64_r64(8, 0);
}
