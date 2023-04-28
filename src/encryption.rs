use crate::{block::Block, key::AESKey};

pub fn encrypt_block<const R: usize>(block: &mut Block, key: impl AESKey<R>) {
    let round_keys = key.round_keys();
}
