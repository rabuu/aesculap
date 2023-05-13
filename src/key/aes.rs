use super::GenericKey;
use super::Key;
use super::{Subkey, Word};

pub type AES128Key = GenericKey<4, 11>;
pub type AES192Key = GenericKey<6, 13>;
pub type AES256Key = GenericKey<8, 15>;

impl Key<11> for AES128Key {
    fn round_keys(&self) -> [Subkey; 11] {
        self.generate_round_keys()
    }
}

impl Key<13> for AES192Key {
    fn round_keys(&self) -> [Subkey; 13] {
        self.generate_round_keys()
    }
}

impl Key<15> for AES256Key {
    fn round_keys(&self) -> [Subkey; 15] {
        self.generate_round_keys()
    }
}

impl AES128Key {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        let key_as_words: Vec<Word> = bytes
            .chunks_exact(4)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .map(|(i, &x)| (x as Word) << ((3 - i) * 8))
                    .sum()
            })
            .collect();

        Self(key_as_words.try_into().unwrap())
    }
}

impl AES192Key {
    pub fn from_bytes(bytes: [u8; 24]) -> Self {
        let key_as_words: Vec<Word> = bytes
            .chunks_exact(4)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .map(|(i, &x)| (x as Word) << ((3 - i) * 8))
                    .sum()
            })
            .collect();

        Self(key_as_words.try_into().unwrap())
    }
}

impl AES256Key {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let key_as_words: Vec<Word> = bytes
            .chunks_exact(4)
            .map(|c| {
                c.iter()
                    .enumerate()
                    .map(|(i, &x)| (x as Word) << ((3 - i) * 8))
                    .sum()
            })
            .collect();

        Self(key_as_words.try_into().unwrap())
    }
}
