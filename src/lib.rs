//! Cryptographically-secure pseudo-random generator based on cryptographic hash function
//!
//! [`HashRng`] is CSPRNG that takes any hashable data as seed and produces a stream
//! of randomness that has the same entropy as the seed. It uses [`udigest`] crate to
//! unambiguously hash the seed.
//!
//! ## Motivation
//! Usually, CSPRNGs have a fixed-size seed. For instance, [`ChaCha20Rng`] has seed of
//! 32 bytes. That means that when you want to derive randomness from data which has entropy
//! exceeding 32 bytes, you'll have to truncate the seed to 32 bytes (e.g. by hashing it),
//! so you won't be able to take advantage of exceeding entropy. This may influence security
//! parameter and make it less secure than desired.
//!
//! [`HashRng`], on other hand, takes advantage of full entropy of the seed. It does so by
//! hashing a counter and then the seed for each block, i.e. the output randomness is:
//!
//! ```text
//! HashRng(seed) = H(0, seed) || H(1, seed) || ...
//! ```
//!
//! ## Security and performance considerations
//! `HashRng` internally uses u64 counter, which means that the period of the sequence is
//! 2<sup>64</sup> times `Digest::OutputSize` (size of hash output).
//!
//! Although we did not perform benchmarks, intuitively, `HashRng` is expected to be noticeably
//! slower than other CSPRNG based on permutations (such as [`ChaCha20Rng`])
//!
//! [`ChaCha20Rng`]: https://docs.rs/rand_chacha/latest/rand_chacha/struct.ChaCha20Rng.html
//!
//! ## Example
//! ```rust
//! use rand::RngCore;
//!
//! #[derive(udigest::Digestable)]
//! pub struct Seed<'a> {
//!     nonce: &'a [u8],
//!     param_a: &'a str,
//!     param_b: &'a str,
//!     // ...
//! }
//!
//! let seed = Seed {
//!     nonce: b"very unpredictable string",
//!     param_a: "some other data containing entropy",
//!     param_b: "something else",
//!     // ...
//! };
//! let mut rng = rand_hash::HashRng::<sha2::Sha256, _>::from_seed(&seed);
//!
//! let mut randomness = [0u8; 256];
//! rng.fill_bytes(&mut randomness);
//! ```

#![no_std]
#![forbid(unused_crate_dependencies, missing_docs)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

#[cfg(test)]
extern crate alloc;

/// CSPRNG that takes any hashable data as the seed
///
/// See [crate] docs for more details.
pub struct HashRng<D: digest::Digest, S: udigest::Digestable> {
    counter: u64,
    seed: S,
    /// buffer = H(counter - 1, seed)
    buffer: digest::Output<D>,
    /// amount of bytes already read from `buffer`
    offset: usize,
}

impl<D: digest::Digest, S: udigest::Digestable> HashRng<D, S> {
    /// Constructs randomness generator from the seed
    pub fn from_seed(seed: S) -> Self {
        let mut r = Self {
            counter: 0,
            buffer: Default::default(),
            offset: 0,
            seed,
        };
        r.advance_buffer();
        r
    }

    fn advance_buffer(&mut self) {
        let counter = self.counter;
        self.counter += 1;
        self.offset = 0;
        self.buffer = udigest::hash::<D>(&udigest::inline_struct!("dfns.rand_hash" {
            counter: counter,
            seed: &self.seed,
        }));
    }
}

impl<D: digest::Digest, S: udigest::Digestable> rand_core::RngCore for HashRng<D, S> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // amount of bytes already written to `dest`
        let mut dest_offset = 0;

        while dest_offset < dest.len() {
            // amount of bytes we copy from `buffer[offset..]` to `dest[dest_offset..]`
            let read_bytes_from_buffer =
                (self.buffer.len() - self.offset).min(dest.len() - dest_offset);

            dest[dest_offset..dest_offset + read_bytes_from_buffer]
                .copy_from_slice(&self.buffer[self.offset..self.offset + read_bytes_from_buffer]);

            self.offset += read_bytes_from_buffer;
            dest_offset += read_bytes_from_buffer;

            if self.offset == self.buffer.len() {
                self.advance_buffer();
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
}

impl<D: digest::Digest, S: udigest::Digestable> From<S> for HashRng<D, S> {
    fn from(seed: S) -> Self {
        Self::from_seed(seed)
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, RngCore};

    use crate::HashRng;

    #[test]
    fn different_window_size() {
        let mut rng = HashRng::<sha2::Sha256, _>::from_seed("foobar");

        let mut buffer = [0u8; 256];

        // Check that it doesn't panic for any window size
        for size in 0..=256 {
            rng.fill_bytes(&mut buffer[..size]);
        }
    }

    #[test]
    fn split_large_randomness_in_chunks() {
        // Here we generate a big random string of big length. Then
        // we reset PRNG state, and generate smaller random strings
        // which length sum up to the length of the big random string.
        //
        // Big random string must be equal to concatenation of smaller
        // strings.

        let mut rng = rand_dev::DevRng::new();
        let seed: [u8; 32] = rng.gen();

        // Generate big random string
        let mut hash_rng = HashRng::<sha2::Sha256, _>::from_seed(seed);
        let big_len = 20_000;
        let mut big_string = alloc::vec![0u8; big_len];
        hash_rng.fill_bytes(&mut big_string);

        // Reset `hash_rng` state
        let mut hash_rng = HashRng::<sha2::Sha256, _>::from_seed(seed);

        // Generate smaller random strings and concatenate them
        let mut concatenation = alloc::vec![];
        while concatenation.len() < big_string.len() {
            let small_len = rng.gen_range(1..=100.min(big_string.len() - concatenation.len()));
            let mut small_string = alloc::vec![0u8; small_len];
            hash_rng.fill_bytes(&mut small_string);

            concatenation.extend_from_slice(&small_string);
        }

        assert_eq!(big_string, concatenation);
    }
}
