use crate::{
    block::Block, init_vec::InitializationVector, key::Key, padding::Padding, EncryptionMode,
};

pub fn encrypt_block<const R: usize, K>(block: &mut Block, key: &K)
where
    K: Key<R>,
{
    let round_keys = key.round_keys();
    debug_assert_eq!(round_keys.len(), R);

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

pub fn encrypt_bytes<const R: usize, K, P>(
    bytes: &[u8],
    key: &K,
    padding: &P,
    mode: EncryptionMode,
) -> Vec<u8>
where
    K: Key<R>,
    P: Padding<16>,
{
    let mut blocks = Block::load(bytes, padding);

    match mode {
        EncryptionMode::ECB => ecb(&mut blocks, key),
        EncryptionMode::CBC(iv) => cbc(&mut blocks, key, iv),
    }

    blocks
        .into_iter()
        .map(|b| b.dump_bytes())
        .flatten()
        .collect()
}

fn ecb<const R: usize, K>(blocks: &mut [Block], key: &K)
where
    K: Key<R>,
{
    for block in blocks {
        encrypt_block(block, key);
    }
}

fn cbc<const R: usize, K>(blocks: &mut [Block], key: &K, iv: InitializationVector)
where
    K: Key<R>,
{
    let mut prev: Block = iv.into();
    for block in blocks {
        *block ^= prev;
        encrypt_block(block, key);
        prev = *block;
    }
}
