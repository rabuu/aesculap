use crate::{
    block::Block,
    init_vec::InitializationVector,
    key::Key,
    padding::{Padding, ZeroPadding},
    EncryptionMode,
};

pub fn decrypt_block<const R: usize, K>(block: &mut Block, key: &K)
where
    K: Key<R>,
{
    let round_keys = key.round_keys();
    debug_assert_eq!(round_keys.len(), R);

    for (i, round_key) in round_keys.into_iter().rev().enumerate() {
        if i == 0 {
            block.add_round_key(round_key);
            continue;
        }

        if i <= R - 2 {
            block.shift_rows_inv();
            block.sub_bytes_inv();
            block.add_round_key(round_key);
            block.mix_columns_inv();
            continue;
        }

        block.shift_rows_inv();
        block.sub_bytes_inv();
        block.add_round_key(round_key);
    }
}

pub fn decrypt_bytes<const R: usize, K, P>(
    bytes: &[u8],
    key: &K,
    padding: Option<P>,
    mode: EncryptionMode,
) -> Result<Vec<u8>, &'static str>
where
    K: Key<R>,
    P: Padding<16>,
{
    if bytes.len() % 16 != 0 {
        return Err("Number of bytes not divisible by 16");
    }

    let mut blocks = Block::load(bytes, &ZeroPadding);

    match mode {
        EncryptionMode::ECB => ecb(&mut blocks, key),
        EncryptionMode::CBC(iv) => cbc(&mut blocks, key, iv),
    }

    let padded_bytes: Vec<[u8; 16]> = blocks.into_iter().map(|b| b.dump_bytes()).collect();

    if let Some(padding) = padding {
        Ok(padding.unpad(&padded_bytes))
    } else {
        Ok(padded_bytes.into_iter().flatten().collect())
    }
}

fn ecb<const R: usize, K>(blocks: &mut [Block], key: &K)
where
    K: Key<R>,
{
    for block in blocks {
        decrypt_block(block, key);
    }
}

fn cbc<const R: usize, K>(blocks: &mut [Block], key: &K, iv: InitializationVector)
where
    K: Key<R>,
{
    let mut prev: Block = iv.into();
    for block in blocks {
        let copy = *block;
        decrypt_block(block, key);
        *block ^= prev;
        prev = copy;
    }
}
