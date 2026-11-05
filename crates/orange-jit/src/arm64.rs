//! `AArch64` code generation.
//!
//! Register use while native code runs:
//!
//! | Host | Role |
//! |---|---|
//! | `x28` | the [`Ctx`](crate::ctx::Ctx) pointer |
//! | `x27` | the gas counter |
//! | `x9`–`x11` | scratch: effective address, host address, temporaries |
//! | `x30` | link register for calls into the runtime |
//! | `x29` | frame pointer: the entry trampoline's frame record, never a guest value |
//! | `x18` | untouched (reserved by the platform) |
//! | the other 23 | guest registers, most used first ([`HOST_REGS`]) |
//!
//! Native code never calls Rust. Every exit stores the guest state back into
//! the context and returns from the entry trampoline, so host calls, nested
//! instances and panics all happen on the Rust side of the boundary.

// Instruction encoding is bit packing of register numbers and immediates
// whose ranges the callers establish; the casts are the encoding.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use orange_vm::isa::{AluImmOp, AluOp, Cond, Instruction, LoadWidth, Reg, StoreWidth};

use crate::code::Emitter;
use crate::ctx::{self, EXIT_FAULT, EXIT_HALT, EXIT_INVALID_JUMP, EXIT_OUT_OF_GAS, EXIT_SITE};
use crate::ctx::{EXIT_TRAP, HEAP, RO, RW, STACK};
use crate::regmap::RegMap;

/// Host registers given to guest registers, in order of preference. `x29`
/// is left out: the platform ABI requires it to address a valid frame record
/// at every instruction, so frame-pointer unwinders (sampling profilers,
/// crash handlers) can walk through native code.
pub(crate) const HOST_REGS: [u8; 23] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 24, 25, 26,
];

/// Largest code size the encodings reach: direct branches and calls span
/// ±128 MiB.
pub(crate) const CODE_LIMIT: usize = 128 << 20;

/// The entry trampoline's signature: context, then the code address to start at.
pub(crate) type Entry = unsafe extern "C" fn(*mut ctx::Ctx, *const u8);

const S0: u8 = 9;
const S1: u8 = 10;
const S2: u8 = 11;
const GAS: u8 = 27;
const CTX: u8 = 28;
const LR: u8 = 30;
/// Register number 31: the zero register in data processing, `sp` in
/// address and immediate-add positions.
const ZR: u8 = 31;
const SP: u8 = 31;

const EQ: u32 = 0;
const NE: u32 = 1;
const HS: u32 = 2;
const LO: u32 = 3;
const HI: u32 = 8;
const GE: u32 = 10;
const LT: u32 = 11;

/// Offsets of the shared runtime routines.
struct Runtime {
    /// Exit routines indexed by `EXIT_*` code.
    exits: [u32; 6],
    /// Region checks for reads of 1, 2, 4 and 8 bytes.
    read: [u32; 4],
    /// Region checks for writes of 1, 2, 4 and 8 bytes.
    write: [u32; 4],
}

/// The emitter for this target.
pub(crate) type Native = Arm64;

/// The `AArch64` emitter.
pub(crate) struct Arm64 {
    code: Vec<u8>,
    map: RegMap,
    rt: Runtime,
    /// Start of each block emitted so far, for backward branches.
    starts: Vec<u32>,
    /// `b` instructions waiting for a block offset: (instruction offset, block).
    fixups: Vec<(u32, u32)>,
}

fn reg(r: u8) -> u32 {
    u32::from(r)
}

impl Arm64 {
    /// An emitter whose runtime is already in place.
    pub(crate) fn new(map: RegMap) -> Arm64 {
        let mut a = Arm64 {
            code: Vec::new(),
            map,
            rt: Runtime {
                exits: [0; 6],
                read: [0; 4],
                write: [0; 4],
            },
            starts: Vec::new(),
            fixups: Vec::new(),
        };
        a.entry();
        let common = a.pos();
        a.exit_common();
        for kind in [
            EXIT_HALT,
            EXIT_TRAP,
            EXIT_FAULT,
            EXIT_INVALID_JUMP,
            EXIT_OUT_OF_GAS,
            EXIT_SITE,
        ] {
            a.rt.exits[kind as usize] = a.pos();
            a.movz(S0, kind as u32, 0);
            a.b(common);
        }
        for (i, n) in [1u32, 2, 4, 8].into_iter().enumerate() {
            a.rt.read[i] = a.pos();
            a.region_check(n, false);
            a.rt.write[i] = a.pos();
            a.region_check(n, true);
        }
        a
    }

    fn pos(&self) -> u32 {
        self.code.len() as u32
    }

    fn emit(&mut self, word: u32) {
        self.code.extend_from_slice(&word.to_le_bytes());
    }

    /// Three-register form: `base | m << 16 | n << 5 | d`.
    fn rrr(&mut self, base: u32, d: u8, n: u8, m: u8) {
        self.emit(base | reg(m) << 16 | reg(n) << 5 | reg(d));
    }

    /// Four-register form (multiply-add): `base | m << 16 | a << 10 | n << 5 | d`.
    fn rrrr(&mut self, base: u32, d: u8, n: u8, m: u8, a: u8) {
        self.emit(base | reg(m) << 16 | reg(a) << 10 | reg(n) << 5 | reg(d));
    }

    /// Register and 12-bit immediate form.
    fn rri(&mut self, base: u32, d: u8, n: u8, imm12: u32) {
        self.emit(base | imm12 << 10 | reg(n) << 5 | reg(d));
    }

    /// Bitfield move: `base | rotate << 16 | top << 10 | n << 5 | d`.
    fn bitfield(&mut self, base: u32, d: u8, n: u8, rotate: u32, top: u32) {
        self.emit(base | rotate << 16 | top << 10 | reg(n) << 5 | reg(d));
    }

    /// `ldr xt, [xn, #off]`, `off` a multiple of 8.
    fn ldr(&mut self, t: u8, n: u8, off: u32) {
        self.rri(0xF940_0000, t, n, off / 8);
    }

    /// `str xt, [xn, #off]`, `off` a multiple of 8.
    fn str(&mut self, t: u8, n: u8, off: u32) {
        self.rri(0xF900_0000, t, n, off / 8);
    }

    /// `stp`/`ldp` of `t1`, `t2` at `[sp + 8 * imm7]` in the addressing mode
    /// `base` selects.
    fn pair(&mut self, base: u32, t1: u8, t2: u8, imm7: i32) {
        self.emit(base | ((imm7 as u32) & 0x7F) << 15 | reg(t2) << 10 | reg(SP) << 5 | reg(t1));
    }

    /// `mov xd, xm` (`orr xd, xzr, xm`).
    fn mov(&mut self, d: u8, m: u8) {
        self.rrr(0xAA00_0000, d, ZR, m);
    }

    /// `cmp xn, xm`.
    fn cmp(&mut self, n: u8, m: u8) {
        self.rrr(0xEB00_0000, ZR, n, m);
    }

    /// `cset xd, cond`.
    fn cset(&mut self, d: u8, cond: u32) {
        self.rrr(0x9A80_0400 | (cond ^ 1) << 12, d, ZR, ZR);
    }

    /// `sxtw xd, wn`.
    fn sxtw(&mut self, d: u8, n: u8) {
        self.rrr(0x9340_7C00, d, n, 0);
    }

    /// `movz xd, #imm16, lsl #(16 * hw)`.
    fn movz(&mut self, d: u8, imm16: u32, hw: u32) {
        self.emit(0xD280_0000 | hw << 21 | imm16 << 5 | reg(d));
    }

    /// Loads a 64-bit constant with the fewest `movz`/`movn`/`movk`.
    fn mov_imm(&mut self, d: u8, v: u64) {
        let chunks = [v & 0xFFFF, (v >> 16) & 0xFFFF, (v >> 32) & 0xFFFF, v >> 48];
        let ones = chunks.iter().filter(|&&c| c == 0xFFFF).count();
        let zeros = chunks.iter().filter(|&&c| c == 0).count();
        // Start from all ones (movn) or all zeros (movz), whichever leaves
        // fewer chunks to patch with movk.
        let (fill, first_op) = if ones > zeros {
            (0xFFFF, 0x9280_0000)
        } else {
            (0, 0xD280_0000)
        };
        let mut first = true;
        for (hw, &c) in chunks.iter().enumerate() {
            if c != fill {
                let (op, imm) = if first {
                    (first_op, if fill == 0 { c } else { !c & 0xFFFF })
                } else {
                    (0xF280_0000, c)
                };
                self.emit(op | (hw as u32) << 21 | (imm as u32) << 5 | reg(d));
                first = false;
            }
        }
        if first {
            // Every chunk equals the fill: 0 or all ones.
            self.emit(first_op | reg(d));
        }
    }

    /// `b target`, `target` already emitted.
    fn b(&mut self, target: u32) {
        let words = (i64::from(target) - i64::from(self.pos())) / 4;
        self.emit(0x1400_0000 | (words as u32 & 0x03FF_FFFF));
    }

    /// `bl target`, `target` already emitted; returns the return offset.
    fn bl(&mut self, target: u32) -> u32 {
        let words = (i64::from(target) - i64::from(self.pos())) / 4;
        self.emit(0x9400_0000 | (words as u32 & 0x03FF_FFFF));
        self.pos()
    }

    /// `b.cond` by a signed number of instructions.
    fn bcond(&mut self, cond: u32, words: i64) {
        self.emit(0x5400_0000 | (words as u32 & 0x7_FFFF) << 5 | cond);
    }

    /// Saves the callee-saved registers, points `x29` at the new frame
    /// record, loads the guest state and jumps to the address in `x1`.
    /// Called as [`Entry`] with the context in `x0`.
    fn entry(&mut self) {
        self.pair(0xA980_0000, 29, LR, -12);
        self.emit(0x9100_03FD); // mov x29, sp
        for (i, r) in [19u8, 21, 23, 25, 27].into_iter().enumerate() {
            self.pair(0xA900_0000, r, r + 1, 2 + 2 * i as i32);
        }
        self.mov(CTX, 0);
        self.mov(LR, 1);
        self.ldr(GAS, CTX, ctx::GAS);
        for (g, h) in self.map.pairs() {
            self.ldr(h, CTX, ctx::reg(g));
        }
        self.emit(0xD61F_0000 | reg(LR) << 5);
    }

    /// Stores the exit site (`x30`), exit kind (`x9`), gas and guest
    /// registers into the context and returns from the entry trampoline.
    fn exit_common(&mut self) {
        self.str(LR, CTX, ctx::EXIT_PC);
        self.str(S0, CTX, ctx::EXIT_KIND);
        self.str(GAS, CTX, ctx::GAS);
        for (g, h) in self.map.pairs() {
            self.str(h, CTX, ctx::reg(g));
        }
        for (i, r) in [19u8, 21, 23, 25, 27].into_iter().enumerate() {
            self.pair(0xA940_0000, r, r + 1, 2 + 2 * i as i32);
        }
        self.pair(0xA8C0_0000, 29, LR, 12);
        self.emit(0xD65F_03C0);
    }

    /// The region check for an access of `n` bytes at the guest address in
    /// `x9`: returns the host address in `x10`, or leaves through the fault
    /// exit with `x30` still naming the access. Regions are searched from
    /// the highest base down; the first base at or below the address picks
    /// the only region that can hold it.
    fn region_check(&mut self, n: u32, write: bool) {
        let regions: &[usize] = if write {
            &[STACK, HEAP, RW]
        } else {
            &[STACK, HEAP, RW, RO]
        };
        let count = regions.len() as i64;
        self.rri(0x9100_0000, S2, S0, n);
        for (k, &r) in regions.iter().enumerate() {
            let k = k as i64;
            self.ldr(S1, CTX, ctx::base(r));
            self.cmp(S0, S1);
            self.bcond(LO, 7);
            self.ldr(S1, CTX, ctx::end(r));
            self.cmp(S2, S1);
            self.bcond(HI, 9 * (count - k) - 5);
            self.ldr(S1, CTX, ctx::bias(r));
            self.rrr(0x8B00_0000, S1, S1, S0);
            self.emit(0xD65F_03C0);
        }
        let fault = self.rt.exits[EXIT_FAULT as usize];
        self.b(fault);
    }

    /// Guest register `r` as an operand of a register-form instruction: its
    /// host register, the zero register, or `scratch` after a load.
    fn src(&mut self, r: Reg, scratch: u8) -> u8 {
        if r == Reg::ZERO {
            return ZR;
        }
        if let Some(h) = self.map.host(r) {
            return h;
        }
        self.ldr(scratch, CTX, ctx::reg(r));
        scratch
    }

    /// As [`Arm64::src`] for positions where register 31 would mean `sp`.
    fn src_nz(&mut self, r: Reg, scratch: u8) -> u8 {
        let s = self.src(r, scratch);
        if s == ZR {
            self.movz(scratch, 0, 0);
            return scratch;
        }
        s
    }

    /// Where to compute a result for guest register `r`.
    fn dst(&self, r: Reg) -> u8 {
        self.map.host(r).unwrap_or(S0)
    }

    /// Stores a result computed in `h` if `r` lives in memory.
    fn commit(&mut self, r: Reg, h: u8) {
        if self.map.host(r).is_none() {
            self.str(h, CTX, ctx::reg(r));
        }
    }

    /// `R[rd] = v`, using `scratch` if `rd` lives in memory.
    fn set_imm(&mut self, rd: Reg, v: u64, scratch: u8) {
        if rd != Reg::ZERO {
            let d = self.map.host(rd).unwrap_or(scratch);
            self.mov_imm(d, v);
            self.commit(rd, d);
        }
    }

    /// `x9 = addr(R[rs1] + off)` (spec 01 §3.1): 32-bit arithmetic, which
    /// zero-extends.
    fn addr(&mut self, rs1: Reg, off: i64) {
        let off = off as u32;
        if rs1 == Reg::ZERO {
            self.mov_imm(S0, u64::from(off));
            return;
        }
        let s = self.src(rs1, S1);
        if off <= 0xFFF {
            self.rri(0x1100_0000, S0, s, off);
        } else if off.wrapping_neg() <= 0xFFF {
            self.rri(0x5100_0000, S0, s, off.wrapping_neg());
        } else {
            self.mov_imm(S2, u64::from(off));
            self.rrr(0x0B00_0000, S0, s, S2);
        }
    }

    /// `rd = rs1 + imm`, 64-bit or 32-bit (`w`).
    fn add_imm(&mut self, w: bool, d: u8, rs1: Reg, imm: i64) {
        let s = self.src_nz(rs1, S1);
        let (add, sub, add_reg) = if w {
            (0x1100_0000, 0x5100_0000, 0x0B00_0000)
        } else {
            (0x9100_0000, 0xD100_0000, 0x8B00_0000)
        };
        if (0..=0xFFF).contains(&imm) {
            self.rri(add, d, s, imm as u32);
        } else if (-0xFFF..0).contains(&imm) {
            self.rri(sub, d, s, (-imm) as u32);
        } else {
            self.mov_imm(S2, imm as u64);
            self.rrr(add_reg, d, s, S2);
        }
    }

    fn alu_imm(&mut self, op: AluImmOp, rd: Reg, rs1: Reg, imm: i64) {
        if rd == Reg::ZERO {
            return;
        }
        let d = self.dst(rd);
        let sh = (imm & 63) as u32;
        let shw = (imm & 31) as u32;
        match op {
            AluImmOp::Addi => self.add_imm(false, d, rs1, imm),
            AluImmOp::Addiw => {
                self.add_imm(true, d, rs1, imm);
                self.sxtw(d, d);
            }
            AluImmOp::Andi | AluImmOp::Ori | AluImmOp::Xori => {
                let s = self.src(rs1, S1);
                self.mov_imm(S2, imm as u64);
                let base = match op {
                    AluImmOp::Andi => 0x8A00_0000,
                    AluImmOp::Ori => 0xAA00_0000,
                    _ => 0xCA00_0000,
                };
                self.rrr(base, d, s, S2);
            }
            AluImmOp::Slti | AluImmOp::Sltiu => {
                let s = self.src_nz(rs1, S1);
                if (0..=0xFFF).contains(&imm) {
                    self.rri(0xF100_0000, ZR, s, imm as u32);
                } else {
                    self.mov_imm(S2, imm as u64);
                    self.cmp(s, S2);
                }
                self.cset(d, if op == AluImmOp::Slti { LT } else { LO });
            }
            AluImmOp::Slli | AluImmOp::Srli | AluImmOp::Srai => {
                let s = self.src(rs1, S1);
                let (base, rotate, top) = match op {
                    AluImmOp::Slli => (0xD340_0000, (64 - sh) & 63, 63 - sh),
                    AluImmOp::Srli => (0xD340_0000, sh, 63),
                    _ => (0x9340_0000, sh, 63),
                };
                self.bitfield(base, d, s, rotate, top);
            }
            AluImmOp::Slliw | AluImmOp::Srliw | AluImmOp::Sraiw => {
                let s = self.src(rs1, S1);
                let (base, rotate, top) = match op {
                    AluImmOp::Slliw => (0x5300_0000, (32 - shw) & 31, 31 - shw),
                    AluImmOp::Srliw => (0x5300_0000, shw, 31),
                    _ => (0x1300_0000, shw, 31),
                };
                self.bitfield(base, d, s, rotate, top);
                self.sxtw(d, d);
            }
        }
        self.commit(rd, d);
    }

    fn alu(&mut self, op: AluOp, rd: Reg, rs1: Reg, rs2: Reg) {
        if rd == Reg::ZERO {
            return;
        }
        let a = self.src(rs1, S1);
        let b = self.src(rs2, S2);
        let d = self.dst(rd);
        // Single instructions, then the 32-bit ones that need a sign extension.
        let simple = match op {
            AluOp::Add => Some((0x8B00_0000, false)),
            AluOp::Sub => Some((0xCB00_0000, false)),
            AluOp::And => Some((0x8A00_0000, false)),
            AluOp::Or => Some((0xAA00_0000, false)),
            AluOp::Xor => Some((0xCA00_0000, false)),
            AluOp::Sll => Some((0x9AC0_2000, false)),
            AluOp::Srl => Some((0x9AC0_2400, false)),
            AluOp::Sra => Some((0x9AC0_2800, false)),
            AluOp::Mulh => Some((0x9B40_7C00, false)),
            AluOp::Mulhu => Some((0x9BC0_7C00, false)),
            AluOp::Mul => Some((0x9B00_7C00, false)),
            AluOp::Addw => Some((0x0B00_0000, true)),
            AluOp::Subw => Some((0x4B00_0000, true)),
            AluOp::Sllw => Some((0x1AC0_2000, true)),
            AluOp::Srlw => Some((0x1AC0_2400, true)),
            AluOp::Sraw => Some((0x1AC0_2800, true)),
            AluOp::Mulw => Some((0x1B00_7C00, true)),
            _ => None,
        };
        if let Some((base, w)) = simple {
            self.rrr(base, d, a, b);
            if w {
                self.sxtw(d, d);
            }
        } else {
            self.alu_long(op, d, a, b);
        }
        self.commit(rd, d);
    }

    /// The operations that take several instructions. Intermediate values go
    /// to `x9` so that `d` may alias either operand.
    fn alu_long(&mut self, op: AluOp, d: u8, a: u8, b: u8) {
        match op {
            AluOp::Slt | AluOp::Sltu => {
                self.cmp(a, b);
                self.cset(d, if op == AluOp::Slt { LT } else { LO });
            }
            AluOp::Mulhsu => {
                // high(signed a × unsigned b) = umulh(a, b) − (a < 0 ? b : 0)
                self.rrr(0x9BC0_7C00, S0, a, b);
                self.cmp(a, ZR);
                self.rrr(0x9A80_0000 | LT << 12, S1, b, ZR);
                self.rrr(0xCB00_0000, d, S0, S1);
            }
            AluOp::Div | AluOp::Divu => {
                // The hardware quotient by zero is 0; spec 02 §6.1 wants all ones.
                let div = if op == AluOp::Div {
                    0x9AC0_0C00
                } else {
                    0x9AC0_0800
                };
                self.rrr(div, S0, a, b);
                self.cmp(b, ZR);
                self.rrr(0xDA80_0000 | NE << 12, d, S0, ZR);
            }
            AluOp::Rem | AluOp::Remu => {
                // a − (a / b) × b; a zero quotient leaves a, as spec 02 §6.1 wants.
                let div = if op == AluOp::Rem {
                    0x9AC0_0C00
                } else {
                    0x9AC0_0800
                };
                self.rrr(div, S0, a, b);
                self.rrrr(0x9B00_8000, d, S0, b, a);
            }
            AluOp::Divw | AluOp::Divuw => {
                let div = if op == AluOp::Divw {
                    0x1AC0_0C00
                } else {
                    0x1AC0_0800
                };
                self.rrr(div, S0, a, b);
                self.rrr(0x6B00_0000, ZR, b, ZR);
                self.rrr(0x5A80_0000 | NE << 12, S0, S0, ZR);
                self.sxtw(d, S0);
            }
            _ => {
                // Remw, Remuw.
                let div = if op == AluOp::Remw {
                    0x1AC0_0C00
                } else {
                    0x1AC0_0800
                };
                self.rrr(div, S0, a, b);
                self.rrrr(0x1B00_8000, S0, S0, b, a);
                self.sxtw(d, S0);
            }
        }
    }

    fn load(&mut self, width: LoadWidth, rd: Reg, rs1: Reg, off: i64) -> u32 {
        self.addr(rs1, off);
        let check = self.rt.read[width.bytes().trailing_zeros() as usize];
        let ret = self.bl(check);
        if rd != Reg::ZERO {
            let d = self.dst(rd);
            let base = match width {
                LoadWidth::B => 0x3980_0000,
                LoadWidth::Bu => 0x3940_0000,
                LoadWidth::H => 0x7980_0000,
                LoadWidth::Hu => 0x7940_0000,
                LoadWidth::W => 0xB980_0000,
                LoadWidth::Wu => 0xB940_0000,
                LoadWidth::D => 0xF940_0000,
            };
            self.rri(base, d, S1, 0);
            self.commit(rd, d);
        }
        ret
    }

    fn store(&mut self, width: StoreWidth, rs1: Reg, rs2: Reg, off: i64) -> u32 {
        self.addr(rs1, off);
        let check = self.rt.write[width.bytes().trailing_zeros() as usize];
        let ret = self.bl(check);
        let v = self.src(rs2, S2);
        let base = match width {
            StoreWidth::B => 0x3900_0000,
            StoreWidth::H => 0x7900_0000,
            StoreWidth::W => 0xB900_0000,
            StoreWidth::D => 0xF900_0000,
        };
        self.rri(base, v, S1, 0);
        ret
    }

    /// `b block`, resolved in [`Emitter::finish`].
    fn jump(&mut self, block: u32) {
        self.fixups.push((self.pos(), block));
        self.emit(0x1400_0000);
    }

    fn branch(&mut self, cond: Cond, rs1: Reg, rs2: Reg, target: u32, current: u32) {
        let a = self.src(rs1, S1);
        let b = self.src(rs2, S2);
        self.cmp(a, b);
        let c = match cond {
            Cond::Eq => EQ,
            Cond::Ne => NE,
            Cond::Lt => LT,
            Cond::Ge => GE,
            Cond::Ltu => LO,
            Cond::Geu => HS,
        };
        if target <= current {
            // Backward: the target is known, and loops usually reach it with
            // a single conditional branch (±1 MiB).
            let words = (i64::from(self.starts[target as usize]) - i64::from(self.pos())) / 4;
            if words >= -(1 << 18) {
                self.bcond(c, words);
                return;
            }
        }
        self.bcond(c ^ 1, 2);
        self.jump(target);
    }

    /// Transfers through the native jump table on the slot address in `x9`
    /// (spec 02 §9). Rotating right by 3 turns an aligned address into its
    /// slot and a misaligned one into a value above any slot count.
    fn indirect(&mut self) -> u32 {
        self.rrr(0x1380_0000 | 3 << 10, S1, S0, S0);
        self.ldr(S2, CTX, ctx::JUMP_SLOTS);
        self.cmp(S1, S2);
        self.bcond(HS, 5);
        self.ldr(S2, CTX, ctx::JUMP_TABLE);
        self.rrr(0xF860_7800, S2, S2, S1);
        self.emit(0xB400_0000 | 2 << 5 | reg(S2));
        self.emit(0xD61F_0000 | reg(S2) << 5);
        self.bl(self.rt.exits[EXIT_INVALID_JUMP as usize])
    }

    fn exit(&mut self, kind: u64) -> u32 {
        self.bl(self.rt.exits[kind as usize])
    }
}

impl Emitter for Arm64 {
    fn here(&self) -> u32 {
        self.pos()
    }

    fn charge(&mut self, cost: u32) -> u32 {
        self.starts.push(self.pos());
        if cost <= 0xFFF {
            self.rri(0xF100_0000, GAS, GAS, cost);
        } else {
            self.mov_imm(S0, u64::from(cost));
            self.rrr(0xEB00_0000, GAS, GAS, S0);
        }
        self.bcond(GE, 2);
        self.exit(EXIT_OUT_OF_GAS)
    }

    fn lower(&mut self, ins: &Instruction, block: u32) -> Option<u32> {
        match *ins {
            Instruction::Trap => Some(self.exit(EXIT_TRAP)),
            Instruction::Halt => Some(self.exit(EXIT_HALT)),
            Instruction::Ecall { .. }
            | Instruction::Sbrk { .. }
            | Instruction::Memcopy { .. }
            | Instruction::Memfill { .. } => Some(self.exit(EXIT_SITE)),
            Instruction::Li { rd, imm } => {
                self.set_imm(rd, imm as u64, S0);
                None
            }
            Instruction::AluImm { op, rd, rs1, imm } => {
                self.alu_imm(op, rd, rs1, imm);
                None
            }
            Instruction::Alu { op, rd, rs1, rs2 } => {
                self.alu(op, rd, rs1, rs2);
                None
            }
            Instruction::Load {
                width,
                rd,
                rs1,
                off,
            } => Some(self.load(width, rd, rs1, off)),
            Instruction::Store {
                width,
                rs1,
                rs2,
                off,
            } => Some(self.store(width, rs1, rs2, off)),
            Instruction::Jump { block: target } => {
                self.jump(target);
                None
            }
            Instruction::Call {
                rd,
                block: target,
                slot,
            } => {
                self.set_imm(rd, 8 * u64::from(slot), S0);
                self.jump(target);
                None
            }
            Instruction::JumpIndirect { rs1, off } => {
                self.addr(rs1, off);
                Some(self.indirect())
            }
            Instruction::CallIndirect { rd, rs1, off, slot } => {
                // The target is read before the link register is written.
                self.addr(rs1, off);
                self.set_imm(rd, 8 * u64::from(slot), S1);
                Some(self.indirect())
            }
            Instruction::Branch {
                cond,
                rs1,
                rs2,
                block: target,
            } => {
                self.branch(cond, rs1, rs2, target, block);
                None
            }
        }
    }

    fn finish(mut self, blocks: &[u32]) -> Vec<u8> {
        for &(at, block) in &self.fixups {
            let words = (i64::from(blocks[block as usize]) - i64::from(at)) / 4;
            let i = at as usize;
            let word = u32::from_le_bytes([
                self.code[i],
                self.code[i + 1],
                self.code[i + 2],
                self.code[i + 3],
            ]) | (words as u32 & 0x03FF_FFFF);
            self.code[i..i + 4].copy_from_slice(&word.to_le_bytes());
        }
        self.code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(f: impl FnOnce(&mut Arm64)) -> Vec<u32> {
        let mut a = Arm64::new(RegMap::choose(
            &orange_vm::module::Program::new(
                orange_vm::module::Module::parse(
                    &{
                        let mut b = orange_vm::builder::ModuleBuilder::new();
                        b.block(&[Instruction::Halt]);
                        b.build()
                    },
                    &|_| true,
                )
                .unwrap(),
                orange_vm::gas::CostTable::V1,
            ),
            &HOST_REGS,
        ));
        let start = a.code.len();
        f(&mut a);
        a.code[start..]
            .chunks(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect()
    }

    #[test]
    fn the_frame_pointer_always_addresses_a_frame_record() {
        // Platform ABI: x29 must name a valid frame record at every
        // instruction, so it is never a guest register, and the trampoline
        // points it at the record it pushes before running guest code.
        assert!(!HOST_REGS.contains(&29));
        assert!(!HOST_REGS.contains(&18));
        let mut all = words(Arm64::entry);
        all.truncate(2);
        // stp x29, x30, [sp, #-96]!; mov x29, sp
        assert_eq!(all, [0xA9BA_7BFD, 0x9100_03FD]);
    }

    #[test]
    fn constants_use_the_shortest_sequence() {
        // Encodings checked against the system assembler.
        assert_eq!(words(|a| a.mov_imm(3, 0)), [0xD280_0003]); // movz x3, #0
        assert_eq!(words(|a| a.mov_imm(3, u64::MAX)), [0x9280_0003]); // movn x3, #0
        assert_eq!(words(|a| a.mov_imm(3, 0x1234)), [0xD282_4683]);
        assert_eq!(
            words(|a| a.mov_imm(3, 0xFFFF_FFFF_FFFF_1234)),
            [0x929D_B963] // movn x3, #0xedcb
        );
        assert_eq!(
            words(|a| a.mov_imm(3, 0x0001_0000_0000_0002)),
            [0xD280_0043, 0xF2E0_0023] // movz x3, #2; movk x3, #1, lsl #48
        );
        assert_eq!(
            words(|a| a.mov_imm(3, 0xFFFF_0000_FFFF_0005)),
            [0x929F_FF43, 0xF2C0_0003] // movn x3, #0xfffa; movk x3, #0, lsl #32
        );
    }

    #[test]
    fn runtime_calls_and_branches_encode_offsets() {
        let w = words(|a| {
            let target = a.pos();
            a.b(target);
            let _ = a.bl(target);
            a.bcond(LT, -2);
        });
        assert_eq!(w, [0x1400_0000, 0x97FF_FFFF, 0x54FF_FFCB]);
    }
}
