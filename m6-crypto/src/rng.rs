//! Entropy source backed by the kernel `GetRandom` syscall.

use core::num::NonZeroU32;
use rand_core::{CryptoRng, Error, RngCore, SeedableRng};

/// Maximum bytes the kernel `GetRandom` self-invocation accepts per call.
const MAX_CHUNK: usize = 256;

/// A cryptographically secure RNG backed directly by the M6 kernel's
/// `GetRandom` self-invocation.
///
/// Each fill traps to the kernel, which draws from the hardware RNG (`RNDR` /
/// platform TRNG) with a timer fallback. Requests larger than 256 bytes are
/// chunked.
///
/// Entropy failure is fatal for [`RngCore::fill_bytes`] (fail closed — never
/// proceed with weak randomness); [`RngCore::try_fill_bytes`] surfaces the
/// error instead. For bulk draws prefer [`M6Rng::seeded_chacha`], which seeds a
/// userspace ChaCha20 CSPRNG once and avoids a kernel trap per draw.
#[derive(Debug, Default, Clone, Copy)]
pub struct M6Rng;

impl M6Rng {
    /// Construct the kernel-backed RNG.
    pub const fn new() -> Self {
        Self
    }

    /// Seed a buffered ChaCha20 CSPRNG from kernel entropy.
    ///
    /// Matches the design's "ChaCha20-based CSPRNG for expansion": draw 32 bytes
    /// of true entropy from the kernel, then expand in userspace.
    pub fn seeded_chacha(&mut self) -> rand_chacha::ChaCha20Rng {
        let mut seed = <rand_chacha::ChaCha20Rng as SeedableRng>::Seed::default();
        self.fill_bytes(&mut seed);
        rand_chacha::ChaCha20Rng::from_seed(seed)
    }
}

impl RngCore for M6Rng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("M6Rng: kernel GetRandom failed -- refusing to proceed with weak entropy");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        for chunk in dest.chunks_mut(MAX_CHUNK) {
            m6_syscall::invoke::get_random(chunk).map_err(|_| {
                // SAFETY of value: CUSTOM_START is a documented non-zero rand_core
                // error code reserved for downstream crates.
                Error::from(NonZeroU32::new(Error::CUSTOM_START).expect("CUSTOM_START is non-zero"))
            })?;
        }
        Ok(())
    }
}

impl CryptoRng for M6Rng {}
