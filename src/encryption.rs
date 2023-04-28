use crate::{block::Block, key::AESKey};

pub fn encrypt_block<const R: usize>(block: &mut Block, key: impl AESKey<R>) {
    let round_keys = key.round_keys();

    for (i, round_key) in round_keys.into_iter().enumerate() {
        if i == 0 {
            block.add_round_key(round_key);
            continue;
        }

        if i <= R - 2 {
            block.sub_bytes();
            block.shift_rows();
            block.mix_columns();
            block.add_round_key(round_key);
            continue;
        }

        block.sub_bytes();
        block.shift_rows();
        block.add_round_key(round_key);
    }
}
