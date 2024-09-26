![License](https://img.shields.io/crates/l/rand_hash.svg)
[![Docs](https://docs.rs/rand_hash/badge.svg)](https://docs.rs/rand_hash)
[![Crates io](https://img.shields.io/crates/v/rand_hash.svg)](https://crates.io/crates/rand_hash)
[![Discord](https://img.shields.io/discord/905194001349627914?logo=discord&logoColor=ffffff&label=Discord)][in Discord]

# Cryptographically-secure pseudo-random generator based on cryptographic hash function

`HashRng` is CSPRNG that takes any hashable data as seed and produces a stream
of randomness that has the same entropy as the seed. It uses [`udigest`](https://docs.rs/udigest) crate to
unambiguously hash the seed.

## Motivation
Usually, CSPRNGs have a fixed-size seed. For instance, [`ChaCha20Rng`](https://docs.rs/rand_chacha/latest/rand_chacha/struct.ChaCha20Rng.html)
has seed of 32 bytes. That means that when you want to derive randomness from data which
has entropy exceeding 32 bytes, you'll have to truncate the seed to 32 bytes (e.g. by hashing it),
so you won't be able to take advantage of exceeding entropy. This may influence security
parameter and make it less secure than desired.

`HashRng`, on other hand, takes advantage of full entropy of the seed. It does so by
hashing a counter and then the seed for each block, i.e. the output randomness is:

```text
HashRng(seed) = H(0, seed) || H(1, seed) || ...
```

## Security and performance considerations
`HashRng` internally uses u64 counter, which means that the period of the sequence is
2<sup>64</sup> times `Digest::OutputSize` (size of hash output).

Although we did not perform benchmarks, intuitively, `HashRng` is expected to be noticeably
slower than other CSPRNG based on permutations (such as `ChaCha20Rng`)

## Example
```rust
use rand::RngCore;

#[derive(udigest::Digestable)]
pub struct Seed<'a> {
    nonce: &'a [u8],
    param_a: &'a str,
    param_b: &'a str,
    // ...
}

let seed = Seed {
    nonce: b"very unpredictable string",
    param_a: "some other data containing entropy",
    param_b: "something else",
    // ...
};
let mut rng = rand_hash::HashRng::<sha2::Sha256, _>::from_seed(&seed);

let mut randomness = [0u8; 256];
rng.fill_bytes(&mut randomness);
```

## Join us in Discord!
Feel free to reach out to us [in Discord]!

[in Discord]: https://discordapp.com/channels/905194001349627914/1285268686147424388
