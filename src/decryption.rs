//! Decryption module
//!
//! This module provides functions to decrypt [Block]s and byte slices.

use crate::block::Block;
use crate::iv::InitializationVector;
use crate::key::Key;
use crate::padding::{Padding, ZeroPadding};
use crate::EncryptionMode;

/// Decrypt a [Block] using a [Key] type
pub fn decrypt_block<const R: usize, K>(block: &mut Block, key: &K)
where
    K: Key<R>,
{
    log::trace!("Decrypt a block");

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

/// Decrypt a byte slice using a [Key] type
///
/// # Parameters
/// - `bytes`: byte slice to decrypt
/// - `key`: [Key] used for decryption
/// - `padding`: how the decrypted bytes should be unpadded
/// - `mode`: [EncryptionMode] that was used for encryption
///
/// # Return value
/// The decryption may fail if the number of encrypted bytes is not a multiple of `16`.
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
    log::trace!("Decrypt bytes");

    if bytes.len() % 16 != 0 {
        let err = "Number of bytes not divisible by 16";
        log::error!("{}", err);
        return Err(err);
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

/// Implementation of [ECB](EncryptionMode) decryption
fn ecb<const R: usize, K>(blocks: &mut [Block], key: &K)
where
    K: Key<R>,
{
    log::trace!("ECB decryption");

    for block in blocks {
        decrypt_block(block, key);
    }
}

/// Implementation of [CBC](EncryptionMode) decryption
fn cbc<const R: usize, K>(blocks: &mut [Block], key: &K, iv: InitializationVector)
where
    K: Key<R>,
{
    log::trace!("CBC decryption");

    let mut prev: Block = iv.into();
    for block in blocks {
        let copy = *block;
        decrypt_block(block, key);
        *block ^= prev;
        prev = copy;
    }
}
