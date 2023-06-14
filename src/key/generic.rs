//! Generic Rijndael key
//!
//! For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/AES_key_schedule).

use crate::lookups::sbox::*;
use crate::util;

use super::{Subkey, Word};

/// Round constants
const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// A generic Rijndael key type with variable size and round number
#[derive(Debug)]
pub struct GenericKey<const N: usize, const R: usize>(pub(super) [Word; N]);

impl<const N: usize, const R: usize> GenericKey<N, R> {
    /// Constructor that takes the original key bytes
    pub fn new(original_key: [Word; N]) -> Self {
        Self(original_key)
    }

    /// AES key schedule
    ///
    /// For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/AES_key_schedule).
    fn key_schedule(&self) -> Vec<Word> {
        let mut words = Vec::with_capacity(R * 4);

        for i in 0..N {
            words.push(self.0[i]);
        }

        for i in N..(R * 4) {
            let prev_round = words[i - N];
            let prev = words[i - 1];

            if i % N == 0 {
                let prev = util::apply_sbox(util::rot_left(prev.to_be_bytes(), 1), SBOX);
                let expanded_word = prev_round
                    ^ util::bytes_as_u32(prev)
                    ^ util::bytes_as_u32([RCON[i / N], 0, 0, 0]);

                words.push(expanded_word);
                continue;
            }

            if N > 6 && i % N == 4 {
                let prev = util::apply_sbox(prev.to_be_bytes(), SBOX);
                let expanded_word = prev_round ^ util::bytes_as_u32(prev);

                words.push(expanded_word);
                continue;
            }

            words.push(prev_round ^ prev);
        }

        debug_assert_eq!(words.len(), R * 4);
        words
    }

    /// Generate a subkey for each round
    pub fn generate_round_keys(&self) -> [Subkey; R] {
        let round_keys: Vec<Subkey> = self
            .key_schedule()
            .chunks_exact(4)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .map(|(i, &x)| (x as Subkey) << ((3 - i) * 32))
                    .fold(0, |acc, x| acc | x)
            })
            .collect();

        round_keys.try_into().unwrap()
    }
}
