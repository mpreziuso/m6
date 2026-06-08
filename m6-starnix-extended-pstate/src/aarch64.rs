// aarch64 extended processor state (FP/SIMD), ported from Fuchsia
// `//src/starnix/lib/extended_pstate/src/aarch64.rs`. no_std; uses core::arch::asm.

use core::arch::asm;
use static_assertions::const_assert_eq;

#[derive(Clone, Copy, Default)]
pub struct State {
    // [arm/v8]: A1.3.1 Execution state
    // 32 registers, 128 bits each
    pub q: [u128; 32],
    // [arm/v8]: A1.5 Advanced SIMD and floating-point support
    pub fpcr: u32,
    pub fpsr: u32,
}

const_assert_eq!(core::mem::size_of::<State>(), 512 + 16);

#[derive(Clone, Copy, Default)]
pub struct Aarch32State {
    // [arm/v8]: E1.3.1 The SIMD and floating-point register file
    // 16 registers, 128 bits each
    pub q: [u128; 16],

    // AArch32 technically has only 32 bits of user space accessible status/control space, see
    // [arm/v8]: G8.2.55 FPSCR, Floating-Point Status and Control Register.
    // The restricted mode implementation maps these to the fpcr/fpsr registers used by
    // AArch64, so we store those here instead of a single u32.
    pub fpcr: u32,
    pub fpsr: u32,
}

const_assert_eq!(core::mem::size_of::<Aarch32State>(), 256 + 16);

// Aarch64 supports aligned and unaligned stores to/from vector registers. Aligned accesses may be
// faster.
const_assert_eq!(core::mem::align_of::<u128>(), 16);

impl Aarch32State {
    #[inline(always)]
    pub(crate) fn save(&mut self) {
        // SAFETY: stores the AArch32-visible vector registers (q0-q15) into the
        // 256-byte aligned `self.q` buffer, then reads fpcr/fpsr. The asm only
        // writes to memory we exclusively own and to the named output operands.
        unsafe {
            asm!(
              "stp  q0,  q1, [{q}, #( 0 * 32)]",
              "stp  q2,  q3, [{q}, #( 1 * 32)]",
              "stp  q4,  q5, [{q}, #( 2 * 32)]",
              "stp  q6,  q7, [{q}, #( 3 * 32)]",
              "stp  q8,  q9, [{q}, #( 4 * 32)]",
              "stp q10, q11, [{q}, #( 5 * 32)]",
              "stp q12, q13, [{q}, #( 6 * 32)]",
              "stp q14, q15, [{q}, #( 7 * 32)]",
              q = in(reg) &self.q,
            );
            asm!(
              "mrs {fpcr:x}, fpcr",
              "mrs {fpsr:x}, fpsr",
              fpcr = out(reg) self.fpcr,
              fpsr = out(reg) self.fpsr,
            );
        }
    }

    #[inline(always)]
    pub(crate) unsafe fn restore(&self) {
        // SAFETY: loads q0-q15 and fpcr/fpsr from this object. The caller
        // guarantees this is used to switch extended processor state (see the
        // safety note on the public `restore`); it clobbers the listed vector
        // registers which are declared as outputs.
        unsafe {
            asm!(
                "ldp  q0,  q1, [{q}, #( 0 * 32)]",
                "ldp  q2,  q3, [{q}, #( 1 * 32)]",
                "ldp  q4,  q5, [{q}, #( 2 * 32)]",
                "ldp  q6,  q7, [{q}, #( 3 * 32)]",
                "ldp  q8,  q9, [{q}, #( 4 * 32)]",
                "ldp q10, q11, [{q}, #( 5 * 32)]",
                "ldp q12, q13, [{q}, #( 6 * 32)]",
                "ldp q14, q15, [{q}, #( 7 * 32)]",
                "msr fpcr, {fpcr:x}",
                "msr fpsr, {fpsr:x}",
                q = in(reg) &self.q,
                fpcr = in(reg) self.fpcr,
                fpsr = in(reg) self.fpsr,
                out( "q0") _,
                out( "q1") _,
                out( "q2") _,
                out( "q3") _,
                out( "q4") _,
                out( "q5") _,
                out( "q6") _,
                out( "q7") _,
                out( "q8") _,
                out( "q9") _,
                out("q10") _,
                out("q11") _,
                out("q12") _,
                out("q13") _,
                out("q14") _,
                out("q15") _,
            );
        }
    }

    pub fn reset(&mut self) {
        *self = Default::default();
    }
}

impl State {
    #[inline(always)]
    pub(crate) fn save(&mut self) {
        // SAFETY: stores the full vector register file (q0-q31) into the aligned
        // `self.q` buffer and reads fpcr/fpsr. Writes only to owned memory and
        // named outputs.
        unsafe {
            asm!(
              "stp  q0,  q1, [{q}, #( 0 * 32)]",
              "stp  q2,  q3, [{q}, #( 1 * 32)]",
              "stp  q4,  q5, [{q}, #( 2 * 32)]",
              "stp  q6,  q7, [{q}, #( 3 * 32)]",
              "stp  q8,  q9, [{q}, #( 4 * 32)]",
              "stp q10, q11, [{q}, #( 5 * 32)]",
              "stp q12, q13, [{q}, #( 6 * 32)]",
              "stp q14, q15, [{q}, #( 7 * 32)]",
              "stp q16, q17, [{q}, #( 8 * 32)]",
              "stp q18, q19, [{q}, #( 9 * 32)]",
              "stp q20, q21, [{q}, #(10 * 32)]",
              "stp q22, q23, [{q}, #(11 * 32)]",
              "stp q24, q25, [{q}, #(12 * 32)]",
              "stp q26, q27, [{q}, #(13 * 32)]",
              "stp q28, q29, [{q}, #(14 * 32)]",
              "stp q30, q31, [{q}, #(15 * 32)]",
              q = in(reg) &self.q,
            );
            asm!(
              "mrs {fpcr:x}, fpcr",
              "mrs {fpsr:x}, fpsr",
              fpcr = out(reg) self.fpcr,
              fpsr = out(reg) self.fpsr,
            );
        }
    }

    #[inline(always)]
    pub(crate) unsafe fn restore(&self) {
        // SAFETY: loads q0-q31 and fpcr/fpsr from this object. The caller
        // guarantees correct usage (see the public `restore` safety note); all
        // clobbered vector registers are declared as outputs.
        unsafe {
            asm!(
                "ldp  q0,  q1, [{q}, #( 0 * 32)]",
                "ldp  q2,  q3, [{q}, #( 1 * 32)]",
                "ldp  q4,  q5, [{q}, #( 2 * 32)]",
                "ldp  q6,  q7, [{q}, #( 3 * 32)]",
                "ldp  q8,  q9, [{q}, #( 4 * 32)]",
                "ldp q10, q11, [{q}, #( 5 * 32)]",
                "ldp q12, q13, [{q}, #( 6 * 32)]",
                "ldp q14, q15, [{q}, #( 7 * 32)]",
                "ldp q16, q17, [{q}, #( 8 * 32)]",
                "ldp q18, q19, [{q}, #( 9 * 32)]",
                "ldp q20, q21, [{q}, #(10 * 32)]",
                "ldp q22, q23, [{q}, #(11 * 32)]",
                "ldp q24, q25, [{q}, #(12 * 32)]",
                "ldp q26, q27, [{q}, #(13 * 32)]",
                "ldp q28, q29, [{q}, #(14 * 32)]",
                "ldp q30, q31, [{q}, #(15 * 32)]",
                "msr fpcr, {fpcr:x}",
                "msr fpsr, {fpsr:x}",
                q = in(reg) &self.q,
                fpcr = in(reg) self.fpcr,
                fpsr = in(reg) self.fpsr,
                out( "q0") _,
                out( "q1") _,
                out( "q2") _,
                out( "q3") _,
                out( "q4") _,
                out( "q5") _,
                out( "q6") _,
                out( "q7") _,
                out( "q8") _,
                out( "q9") _,
                out("q10") _,
                out("q11") _,
                out("q12") _,
                out("q13") _,
                out("q14") _,
                out("q15") _,
                out("q16") _,
                out("q17") _,
                out("q18") _,
                out("q19") _,
                out("q20") _,
                out("q21") _,
                out("q22") _,
                out("q23") _,
                out("q24") _,
                out("q25") _,
                out("q26") _,
                out("q27") _,
                out("q28") _,
                out("q29") _,
                out("q30") _,
                out("q31") _,
            );
        }
    }

    pub fn reset(&mut self) {
        *self = Default::default();
    }
}
