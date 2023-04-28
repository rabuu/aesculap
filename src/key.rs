use crate::sbox::*;
use crate::util;

type Word = u32;
type Subkey = u128;

const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

#[derive(Debug)]
pub struct Key<const N: usize, const R: usize>([Word; N]);

impl<const N: usize, const R: usize> Key<N, R> {
    pub fn new(key: [Word; N]) -> Self {
        Self(key)
    }

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

    pub fn generate_round_keys(&self) -> [Subkey; R] {
        let round_keys: Vec<Subkey> = self
            .key_schedule()
            .chunks_exact(4)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .map(|(i, &x)| (x as Subkey) << (3 - i) * 32)
                    .fold(0, |acc, x| acc | x)
            })
            .collect();

        round_keys.try_into().unwrap()
    }
}

pub type AES128Key = Key<4, 11>;
pub type AES192Key = Key<6, 13>;
pub type AES256Key = Key<8, 15>;

pub trait AESKey<const R: usize> {
    fn round_keys(&self) -> [Subkey; R];
}

impl AESKey<11> for AES128Key {
    fn round_keys(&self) -> [Subkey; 11] {
        self.generate_round_keys()
    }
}

impl AESKey<13> for AES192Key {
    fn round_keys(&self) -> [Subkey; 13] {
        self.generate_round_keys()
    }
}

impl AESKey<15> for AES256Key {
    fn round_keys(&self) -> [Subkey; 15] {
        self.generate_round_keys()
    }
}
