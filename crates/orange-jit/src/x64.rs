//! x86-64 code generation (System V calling convention, Unix).
//!
//! Register use while native code runs:
//!
//! | Host | Role |
//! |---|---|
//! | `r15` | the [`Ctx`](crate::ctx::Ctx) pointer |
//! | `r14` | the gas counter |
//! | `rax`, `rcx`, `rdx` | scratch; also the fixed operands of `mul`, `div` and shifts |
//! | `rsp` | the native stack |
//! | the other 10 | guest registers, most used first ([`HOST_REGS`]) |
//!
//! Sixteen host registers cannot hold thirty-one guest registers (ADR 0015):
//! the ten most used live in host registers, the rest in the context.
//! Native code never calls Rust; every exit stores the guest state and
//! returns from the entry trampoline.

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

const RAX: u8 = 0;
const RCX: u8 = 1;
const RDX: u8 = 2;
const RBX: u8 = 3;
const RBP: u8 = 5;
const RSI: u8 = 6;
const RDI: u8 = 7;
const GAS: u8 = 14;
const CTX: u8 = 15;

/// Host registers given to guest registers, in order of preference.
pub(crate) const HOST_REGS: [u8; 10] = [RBX, RBP, RSI, RDI, 8, 9, 10, 11, 12, 13];

/// Largest code size: rel32 branches reach ±2 GiB; stay well inside.
pub(crate) const CODE_LIMIT: usize = 1 << 30;

/// The entry trampoline's signature: context, then the code address to start at.
pub(crate) type Entry = unsafe extern "sysv64" fn(*mut ctx::Ctx, *const u8);

/// The emitter for this target.
pub(crate) type Native = X64;

const B: u8 = 0x2;
const AE: u8 = 0x3;
const E: u8 = 0x4;
const NE: u8 = 0x5;
const A: u8 = 0x7;
const L: u8 = 0xC;
const GE: u8 = 0xD;

/// Offsets of the shared runtime routines.
struct Runtime {
    exits: [u32; 6],
    read: [u32; 4],
    write: [u32; 4],
}

/// The x86-64 emitter.
pub(crate) struct X64 {
    code: Vec<u8>,
    map: RegMap,
    rt: Runtime,
    /// rel32 fields waiting for a block offset: (field offset, block).
    fixups: Vec<(u32, u32)>,
}

impl X64 {
    /// An emitter whose runtime is already in place.
    pub(crate) fn new(map: RegMap) -> X64 {
        let mut a = X64 {
            code: Vec::new(),
            map,
            rt: Runtime {
                exits: [0; 6],
                read: [0; 4],
                write: [0; 4],
            },
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
            a.byte(0xB8);
            a.dword(kind as u32);
            a.jmp(common);
        }
        for (i, n) in [1u8, 2, 4, 8].into_iter().enumerate() {
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

    fn byte(&mut self, b: u8) {
        self.code.push(b);
    }

    fn bytes(&mut self, b: &[u8]) {
        self.code.extend_from_slice(b);
    }

    fn dword(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }

    /// A REX prefix, emitted when any bit is set or `force` asks for one
    /// (byte access to `spl`, `bpl`, `sil`, `dil`).
    fn rex(&mut self, w: bool, reg: u8, base: u8, force: bool) {
        let v = 0x40 | u8::from(w) << 3 | (reg >> 3 & 1) << 2 | (base >> 3 & 1);
        if v != 0x40 || force {
            self.byte(v);
        }
    }

    /// `op reg, rm` with a register operand in r/m.
    fn rr(&mut self, w: bool, op: &[u8], reg: u8, rm: u8) {
        self.rex(w, reg, rm, false);
        self.bytes(op);
        self.byte(0xC0 | (reg & 7) << 3 | (rm & 7));
    }

    /// The `ModRM` and displacement of `[base + disp]`. Bases are only ever
    /// `r15`, `rax` or `rdx`, none of which needs a SIB byte.
    fn mem(&mut self, reg: u8, base: u8, disp: u32) {
        let r = (reg & 7) << 3 | (base & 7);
        if disp == 0 {
            self.byte(r);
        } else if disp < 0x80 {
            self.byte(0x40 | r);
            self.byte(disp as u8);
        } else {
            self.byte(0x80 | r);
            self.dword(disp);
        }
    }

    /// `op reg, [base + disp]`.
    fn rm(&mut self, w: bool, op: &[u8], reg: u8, base: u8, disp: u32) {
        self.rex(w, reg, base, false);
        self.bytes(op);
        self.mem(reg, base, disp);
    }

    /// `mov r64, imm64`.
    fn movabs(&mut self, r: u8, v: u64) {
        self.rex(true, 0, r, false);
        self.byte(0xB8 | (r & 7));
        self.bytes(&v.to_le_bytes());
    }

    /// `movsxd rax, eax`.
    fn movsxd(&mut self) {
        self.rr(true, &[0x63], RAX, RAX);
    }

    /// `jmp target`, `target` already emitted.
    fn jmp(&mut self, target: u32) {
        self.byte(0xE9);
        let rel = i64::from(target) - i64::from(self.pos()) - 4;
        self.dword(rel as u32);
    }

    /// `call target`, `target` already emitted; returns the return offset.
    fn call(&mut self, target: u32) -> u32 {
        self.byte(0xE8);
        let rel = i64::from(target) - i64::from(self.pos()) - 4;
        self.dword(rel as u32);
        self.pos()
    }

    /// A short forward jump (`jcc` or, with `None`, `jmp`) to be bound with
    /// [`X64::bind8`].
    fn jump8(&mut self, cc: Option<u8>) -> usize {
        self.byte(cc.map_or(0xEB, |c| 0x70 | c));
        self.byte(0);
        self.code.len() - 1
    }

    fn bind8(&mut self, at: usize) {
        let rel = self.code.len() - (at + 1);
        assert!(rel < 0x80, "short jump out of range");
        self.code[at] = rel as u8;
    }

    /// Saves the callee-saved registers, loads the guest state and jumps to
    /// the address in `rsi`. Called as [`Entry`] with the context in `rdi`.
    fn entry(&mut self) {
        self.bytes(&[0x53, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
        self.rr(true, &[0x8B], CTX, RDI);
        self.rr(true, &[0x8B], RAX, RSI);
        self.rm(true, &[0x8B], GAS, CTX, ctx::GAS);
        for (g, h) in self.map.pairs() {
            self.rm(true, &[0x8B], h, CTX, ctx::reg(g));
        }
        self.rr(false, &[0xFF], 4, RAX);
    }

    /// Pops the exit site, stores it, the exit kind (`rax`), gas and guest
    /// registers into the context, and returns from the entry trampoline.
    fn exit_common(&mut self) {
        self.byte(0x59);
        self.rm(true, &[0x89], RCX, CTX, ctx::EXIT_PC);
        self.rm(true, &[0x89], RAX, CTX, ctx::EXIT_KIND);
        self.rm(true, &[0x89], GAS, CTX, ctx::GAS);
        for (g, h) in self.map.pairs() {
            self.rm(true, &[0x89], h, CTX, ctx::reg(g));
        }
        self.bytes(&[
            0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5D, 0x5B, 0xC3,
        ]);
    }

    /// The region check for an access of `n` bytes at the guest address in
    /// `rax`: returns the host address in `rdx`, or leaves through the fault
    /// exit with the access's return address still on the stack.
    fn region_check(&mut self, n: u8, write: bool) {
        let regions: &[usize] = if write {
            &[STACK, HEAP, RW]
        } else {
            &[STACK, HEAP, RW, RO]
        };
        self.rm(true, &[0x8D], RCX, RAX, u32::from(n));
        let mut faults = Vec::new();
        for &r in regions {
            self.rm(true, &[0x3B], RAX, CTX, ctx::base(r));
            let below = self.jump8(Some(B));
            self.rm(true, &[0x3B], RCX, CTX, ctx::end(r));
            faults.push(self.jump8(Some(A)));
            self.rm(true, &[0x8B], RDX, CTX, ctx::bias(r));
            self.rr(true, &[0x03], RDX, RAX);
            self.byte(0xC3);
            self.bind8(below);
        }
        for at in faults {
            self.bind8(at);
        }
        self.jmp(self.rt.exits[EXIT_FAULT as usize]);
    }

    /// `dst = R[g]`, `dst` a scratch register.
    fn load(&mut self, dst: u8, g: Reg) {
        if g == Reg::ZERO {
            self.rr(false, &[0x33], dst, dst);
        } else if let Some(h) = self.map.host(g) {
            self.rr(true, &[0x8B], dst, h);
        } else {
            self.rm(true, &[0x8B], dst, CTX, ctx::reg(g));
        }
    }

    /// `R[g]` as a register: its host register, or `scratch` after a load.
    fn opnd(&mut self, g: Reg, scratch: u8) -> u8 {
        if let Some(h) = self.map.host(g) {
            return h;
        }
        self.load(scratch, g);
        scratch
    }

    /// `R[g] = src` for `g` other than register 0.
    fn store(&mut self, g: Reg, src: u8) {
        match self.map.host(g) {
            Some(h) => self.rr(true, &[0x8B], h, src),
            None => self.rm(true, &[0x89], src, CTX, ctx::reg(g)),
        }
    }

    /// `R[rd] = v` without touching the scratch registers when `v` fits a
    /// sign-extended 32-bit immediate.
    fn set_imm(&mut self, rd: Reg, v: u64) {
        if rd == Reg::ZERO {
            return;
        }
        if let Ok(i) = i32::try_from(v as i64) {
            match self.map.host(rd) {
                Some(h) => self.rr(true, &[0xC7], 0, h),
                None => self.rm(true, &[0xC7], 0, CTX, ctx::reg(rd)),
            }
            self.dword(i as u32);
        } else {
            self.movabs(RAX, v);
            self.store(rd, RAX);
        }
    }

    /// `eax = addr(R[rs1] + off)` (spec 01 §3.1); 32-bit arithmetic
    /// zero-extends into `rax`.
    fn addr(&mut self, rs1: Reg, off: i64) {
        let off = off as u32;
        if rs1 == Reg::ZERO {
            self.byte(0xB8);
        } else {
            match self.map.host(rs1) {
                Some(h) => self.rr(false, &[0x8B], RAX, h),
                None => self.rm(false, &[0x8B], RAX, CTX, ctx::reg(rs1)),
            }
            self.rr(false, &[0x81], 0, RAX);
        }
        self.dword(off);
    }

    /// `rax op= imm` for the group-1 operation `ext`.
    fn op_imm(&mut self, ext: u8, imm: i64) {
        if let Ok(i) = i32::try_from(imm) {
            self.rr(true, &[0x81], ext, RAX);
            self.dword(i as u32);
        } else {
            self.movabs(RCX, imm as u64);
            self.rr(true, &[ext << 3 | 3], RAX, RCX);
        }
    }

    /// `eax = cc ? 1 : 0` from the flags.
    fn setcc(&mut self, cc: u8) {
        self.rr(false, &[0x0F, 0x90 | cc], 0, RAX);
        self.rr(false, &[0x0F, 0xB6], RAX, RAX);
    }

    fn alu_imm(&mut self, op: AluImmOp, rd: Reg, rs1: Reg, imm: i64) {
        if rd == Reg::ZERO {
            return;
        }
        self.load(RAX, rs1);
        match op {
            AluImmOp::Addi | AluImmOp::Addiw | AluImmOp::Andi | AluImmOp::Ori | AluImmOp::Xori => {
                let ext = match op {
                    AluImmOp::Andi => 4,
                    AluImmOp::Ori => 1,
                    AluImmOp::Xori => 6,
                    _ => 0,
                };
                self.op_imm(ext, imm);
                if op == AluImmOp::Addiw {
                    self.movsxd();
                }
            }
            AluImmOp::Slti | AluImmOp::Sltiu => {
                self.op_imm(7, imm);
                self.setcc(if op == AluImmOp::Slti { L } else { B });
            }
            AluImmOp::Slli | AluImmOp::Srli | AluImmOp::Srai => {
                let ext = match op {
                    AluImmOp::Slli => 4,
                    AluImmOp::Srli => 5,
                    _ => 7,
                };
                self.rr(true, &[0xC1], ext, RAX);
                self.byte((imm & 63) as u8);
            }
            AluImmOp::Slliw | AluImmOp::Srliw | AluImmOp::Sraiw => {
                let ext = match op {
                    AluImmOp::Slliw => 4,
                    AluImmOp::Srliw => 5,
                    _ => 7,
                };
                self.rr(false, &[0xC1], ext, RAX);
                self.byte((imm & 31) as u8);
                self.movsxd();
            }
        }
        self.store(rd, RAX);
    }

    fn alu(&mut self, op: AluOp, rd: Reg, rs1: Reg, rs2: Reg) {
        if rd == Reg::ZERO {
            return;
        }
        let out = match op {
            AluOp::Add
            | AluOp::Sub
            | AluOp::And
            | AluOp::Or
            | AluOp::Xor
            | AluOp::Addw
            | AluOp::Subw => {
                self.load(RAX, rs1);
                let b = self.opnd(rs2, RCX);
                let opcode = match op {
                    AluOp::Sub | AluOp::Subw => 0x2B,
                    AluOp::And => 0x23,
                    AluOp::Or => 0x0B,
                    AluOp::Xor => 0x33,
                    _ => 0x03,
                };
                self.rr(true, &[opcode], RAX, b);
                if matches!(op, AluOp::Addw | AluOp::Subw) {
                    self.movsxd();
                }
                RAX
            }
            AluOp::Sll | AluOp::Srl | AluOp::Sra | AluOp::Sllw | AluOp::Srlw | AluOp::Sraw => {
                // x86 masks the count in cl by 63 (by 31 for 32-bit), as RISC-V does.
                self.load(RCX, rs2);
                self.load(RAX, rs1);
                let (w, ext) = match op {
                    AluOp::Sll => (true, 4),
                    AluOp::Srl => (true, 5),
                    AluOp::Sra => (true, 7),
                    AluOp::Sllw => (false, 4),
                    AluOp::Srlw => (false, 5),
                    _ => (false, 7),
                };
                self.rr(w, &[0xD3], ext, RAX);
                if !w {
                    self.movsxd();
                }
                RAX
            }
            AluOp::Slt | AluOp::Sltu => {
                self.load(RAX, rs1);
                let b = self.opnd(rs2, RCX);
                self.rr(true, &[0x3B], RAX, b);
                self.setcc(if op == AluOp::Slt { L } else { B });
                RAX
            }
            AluOp::Mul | AluOp::Mulw => {
                self.load(RAX, rs1);
                let b = self.opnd(rs2, RCX);
                self.rr(true, &[0x0F, 0xAF], RAX, b);
                if op == AluOp::Mulw {
                    self.movsxd();
                }
                RAX
            }
            AluOp::Mulh | AluOp::Mulhu | AluOp::Mulhsu => {
                self.load(RAX, rs1);
                let b = self.opnd(rs2, RCX);
                self.rr(true, &[0xF7], if op == AluOp::Mulh { 5 } else { 4 }, b);
                if op == AluOp::Mulhsu {
                    // high(signed a × unsigned b) = mulhu(a, b) − (a < 0 ? b : 0)
                    self.load(RAX, rs1);
                    self.rr(true, &[0xC1], 7, RAX);
                    self.byte(63);
                    self.rr(true, &[0x23], RAX, b);
                    self.rr(true, &[0x2B], RDX, RAX);
                }
                RDX
            }
            _ => self.divide(op, rs1, rs2),
        };
        self.store(rd, out);
    }

    /// Division and remainder in all eight forms. The hardware faults on a
    /// zero divisor and on the most negative value divided by −1; spec 02
    /// §6.1 defines both, so they are branched around. Result in `rax`.
    fn divide(&mut self, op: AluOp, rs1: Reg, rs2: Reg) -> u8 {
        let (signed, rem, w) = match op {
            AluOp::Div => (true, false, true),
            AluOp::Divu => (false, false, true),
            AluOp::Rem => (true, true, true),
            AluOp::Remu => (false, true, true),
            AluOp::Divw => (true, false, false),
            AluOp::Divuw => (false, false, false),
            AluOp::Remw => (true, true, false),
            _ => (false, true, false),
        };
        self.load(RAX, rs1);
        let b = self.opnd(rs2, RCX);
        self.rr(w, &[0x85], b, b);
        let zero = self.jump8(Some(E));
        let mut done = Vec::new();
        if signed {
            self.rr(w, &[0x83], 7, b);
            self.byte(0xFF);
            let normal = self.jump8(Some(NE));
            if rem {
                self.rr(false, &[0x33], RAX, RAX);
            } else {
                self.rr(w, &[0xF7], 3, RAX);
            }
            done.push(self.jump8(None));
            self.bind8(normal);
            if w {
                self.byte(0x48);
            }
            self.byte(0x99);
            self.rr(w, &[0xF7], 7, b);
        } else {
            self.rr(false, &[0x33], RDX, RDX);
            self.rr(w, &[0xF7], 6, b);
        }
        if rem {
            self.rr(true, &[0x8B], RAX, RDX);
        }
        done.push(self.jump8(None));
        self.bind8(zero);
        if !rem {
            self.rr(true, &[0xC7], 0, RAX);
            self.dword(u32::MAX);
        }
        for at in done {
            self.bind8(at);
        }
        if !w {
            self.movsxd();
        }
        RAX
    }

    fn load_ins(&mut self, width: LoadWidth, rd: Reg, rs1: Reg, off: i64) -> u32 {
        self.addr(rs1, off);
        let ret = self.call(self.rt.read[width.bytes().trailing_zeros() as usize]);
        if rd != Reg::ZERO {
            let d = self.map.host(rd).unwrap_or(RAX);
            let (w, op): (bool, &[u8]) = match width {
                LoadWidth::B => (true, &[0x0F, 0xBE]),
                LoadWidth::Bu => (false, &[0x0F, 0xB6]),
                LoadWidth::H => (true, &[0x0F, 0xBF]),
                LoadWidth::Hu => (false, &[0x0F, 0xB7]),
                LoadWidth::W => (true, &[0x63]),
                LoadWidth::Wu => (false, &[0x8B]),
                LoadWidth::D => (true, &[0x8B]),
            };
            self.rm(w, op, d, RDX, 0);
            if self.map.host(rd).is_none() {
                self.store(rd, RAX);
            }
        }
        ret
    }

    fn store_ins(&mut self, width: StoreWidth, rs1: Reg, rs2: Reg, off: i64) -> u32 {
        self.addr(rs1, off);
        let ret = self.call(self.rt.write[width.bytes().trailing_zeros() as usize]);
        let v = self.opnd(rs2, RCX);
        match width {
            StoreWidth::B => {
                self.rex(false, v, RDX, v >= 4);
                self.byte(0x88);
                self.mem(v, RDX, 0);
            }
            StoreWidth::H => {
                self.byte(0x66);
                self.rm(false, &[0x89], v, RDX, 0);
            }
            StoreWidth::W => self.rm(false, &[0x89], v, RDX, 0),
            StoreWidth::D => self.rm(true, &[0x89], v, RDX, 0),
        }
        ret
    }

    /// A rel32 field resolved to `block` in [`Emitter::finish`].
    fn block_rel(&mut self, block: u32) {
        self.fixups.push((self.pos(), block));
        self.dword(0);
    }

    fn branch(&mut self, cond: Cond, rs1: Reg, rs2: Reg, target: u32) {
        let a = self.opnd(rs1, RAX);
        let b = self.opnd(rs2, RCX);
        self.rr(true, &[0x39], b, a);
        let cc = match cond {
            Cond::Eq => E,
            Cond::Ne => NE,
            Cond::Lt => L,
            Cond::Ge => GE,
            Cond::Ltu => B,
            Cond::Geu => AE,
        };
        self.bytes(&[0x0F, 0x80 | cc]);
        self.block_rel(target);
    }

    /// Transfers through the native jump table on the slot address in `eax`
    /// (spec 02 §9). Rotating right by 3 turns an aligned address into its
    /// slot and a misaligned one into a value above any slot count.
    fn indirect(&mut self) -> u32 {
        self.rr(false, &[0x8B], RCX, RAX);
        self.rr(false, &[0xC1], 1, RCX);
        self.byte(3);
        self.rm(true, &[0x3B], RCX, CTX, ctx::JUMP_SLOTS);
        let outside = self.jump8(Some(AE));
        self.rm(true, &[0x8B], RDX, CTX, ctx::JUMP_TABLE);
        self.bytes(&[0x48, 0x8B, 0x14, 0xCA]);
        self.rr(true, &[0x85], RDX, RDX);
        let empty = self.jump8(Some(E));
        self.rr(false, &[0xFF], 4, RDX);
        self.bind8(outside);
        self.bind8(empty);
        self.call(self.rt.exits[EXIT_INVALID_JUMP as usize])
    }

    fn exit(&mut self, kind: u64) -> u32 {
        self.call(self.rt.exits[kind as usize])
    }
}

impl Emitter for X64 {
    fn here(&self) -> u32 {
        self.pos()
    }

    fn charge(&mut self, cost: u32) -> u32 {
        if cost < 0x80 {
            self.rr(true, &[0x83], 5, GAS);
            self.byte(cost as u8);
        } else {
            self.rr(true, &[0x81], 5, GAS);
            self.dword(cost);
        }
        self.bytes(&[0x70 | GE, 5]);
        self.exit(EXIT_OUT_OF_GAS)
    }

    fn lower(&mut self, ins: &Instruction, _block: u32) -> Option<u32> {
        match *ins {
            Instruction::Trap => Some(self.exit(EXIT_TRAP)),
            Instruction::Halt => Some(self.exit(EXIT_HALT)),
            Instruction::Ecall { .. }
            | Instruction::Sbrk { .. }
            | Instruction::Memcopy { .. }
            | Instruction::Memfill { .. } => Some(self.exit(EXIT_SITE)),
            Instruction::Li { rd, imm } => {
                self.set_imm(rd, imm as u64);
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
            } => Some(self.load_ins(width, rd, rs1, off)),
            Instruction::Store {
                width,
                rs1,
                rs2,
                off,
            } => Some(self.store_ins(width, rs1, rs2, off)),
            Instruction::Jump { block } => {
                self.byte(0xE9);
                self.block_rel(block);
                None
            }
            Instruction::Call { rd, block, slot } => {
                self.set_imm(rd, 8 * u64::from(slot));
                self.byte(0xE9);
                self.block_rel(block);
                None
            }
            Instruction::JumpIndirect { rs1, off } => {
                self.addr(rs1, off);
                Some(self.indirect())
            }
            Instruction::CallIndirect { rd, rs1, off, slot } => {
                // The target is read before the link register is written; the
                // link value always fits an immediate, so `rax` survives.
                self.addr(rs1, off);
                self.set_imm(rd, 8 * u64::from(slot));
                Some(self.indirect())
            }
            Instruction::Branch {
                cond,
                rs1,
                rs2,
                block,
            } => {
                self.branch(cond, rs1, rs2, block);
                None
            }
        }
    }

    fn finish(mut self, blocks: &[u32]) -> Vec<u8> {
        for &(at, block) in &self.fixups {
            let rel = i64::from(blocks[block as usize]) - i64::from(at) - 4;
            let i = at as usize;
            self.code[i..i + 4].copy_from_slice(&(rel as u32).to_le_bytes());
        }
        self.code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::many_single_char_names)]
    fn emitted(f: impl FnOnce(&mut X64)) -> Vec<u8> {
        let mut b = orange_vm::builder::ModuleBuilder::new();
        b.block(&[Instruction::Halt]);
        let m = orange_vm::module::Module::parse(&b.build(), &|_| true).unwrap();
        let p = orange_vm::module::Program::new(m, orange_vm::gas::CostTable::V1);
        let mut a = X64::new(RegMap::choose(&p, &HOST_REGS));
        let start = a.code.len();
        f(&mut a);
        a.code[start..].to_vec()
    }

    #[test]
    fn encodings_match_the_reference_assembler() {
        // mov rax, [r15 + 8]; mov [r15 + 0x100], r14; mov rdx, [rdx]
        assert_eq!(
            emitted(|a| {
                a.rm(true, &[0x8B], RAX, CTX, 8);
                a.rm(true, &[0x89], GAS, CTX, 0x100);
                a.rm(true, &[0x8B], RDX, RDX, 0);
            }),
            [
                0x49, 0x8B, 0x47, 0x08, 0x4D, 0x89, 0xB7, 0x00, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x12
            ]
        );
        // movabs rcx, 0x1122334455667788; mov byte [rdx], sil; movsxd rax, eax
        assert_eq!(
            emitted(|a| {
                a.movabs(RCX, 0x1122_3344_5566_7788);
                a.rex(false, RSI, RDX, true);
                a.byte(0x88);
                a.mem(RSI, RDX, 0);
                a.movsxd();
            }),
            [
                0x48, 0xB9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x40, 0x88, 0x32, 0x48,
                0x63, 0xC0
            ]
        );
    }
}
