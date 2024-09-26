#![doc = include_str!("../README.md")]
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
            let len = (self.buffer.len() - self.offset).min(dest.len() - dest_offset);

            dest[dest_offset..dest_offset + len]
                .copy_from_slice(&self.buffer[self.offset..self.offset + len]);

            self.offset += len;
            dest_offset += len;

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

impl<D: digest::Digest, S: udigest::Digestable> rand_core::CryptoRng for HashRng<D, S> {}

impl<D: digest::Digest, S: udigest::Digestable> From<S> for HashRng<D, S> {
    fn from(seed: S) -> Self {
        Self::from_seed(seed)
    }
}

pub mod builder {
    //! Alternative way to instantiate `HashRng`
    //!
    //! ## Example
    //! ```rust
    //! let rng = rand_hash::builder::with_seed("foobar")
    //!     .with_digest::<sha2::Sha256>();
    //! ```

    /// Specifies a seed to use
    pub fn with_seed<S>(seed: S) -> WithSeed<S> {
        WithSeed { seed }
    }

    /// Specifies a digest to use
    pub fn with_digest<D>() -> WithDigest<D> {
        WithDigest(core::marker::PhantomData)
    }

    /// Builder that holds a seed
    pub struct WithSeed<S> {
        seed: S,
    }
    impl<S> WithSeed<S> {
        /// Specifies a choice of digest and returns the instance of `HashRng`
        pub fn with_digest<D>(self) -> super::HashRng<D, S>
        where
            D: digest::Digest,
            S: udigest::Digestable,
        {
            super::HashRng::<D, S>::from_seed(self.seed)
        }
    }

    /// Builder that holds a choice of digest
    pub struct WithDigest<D>(core::marker::PhantomData<D>);
    impl<D> WithDigest<D> {
        /// Specifies a seed to use and returns the instance of `HashRng`
        pub fn with_seed<S>(&self, seed: S) -> super::HashRng<D, S>
        where
            D: digest::Digest,
            S: udigest::Digestable,
        {
            super::HashRng::<D, S>::from_seed(seed)
        }
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
