//! AES block module
//!
//! This module provides the AES [Block] abstraction
//! that defines how to operate on the 4x4 byte chunks (-> blocks) that AES uses to encrypt data.

use std::ops;

use crate::lookups::{gmul::*, sbox::*};
use crate::padding::Padding;
use crate::util;

/// Size of the payload of a [Block] (in bytes)
pub const BLOCK_SIZE: usize = 16;

/// The AES block abstraction
///
/// Internally a block is just 4x4 bytes.
/// AES defines a set of instructions that operate on this matrix.
/// These instructions are implemented as methods of this struct.
///
/// - [Substitute bytes](Self::sub_bytes) and its [inverse](Self::sub_bytes_inv)
/// - [Shift rows](Self::shift_rows) and its [inverse](Self::shift_rows_inv)
/// - [Mix columns](Self::mix_columns) and its [inverse](Self::mix_columns_inv)
/// - [Add round key](Self::add_round_key)
///
/// For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Description_of_the_ciphers).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Block {
    state: [[u8; 4]; 4],
}

impl Block {
    /// Constructor that takes a 4x4 byte matrix
    pub fn new(state: [[u8; 4]; 4]) -> Self {
        Self { state }
    }

    /// Constructor that takes a continuous 16 byte array
    pub fn from_bytes(bytes: [u8; BLOCK_SIZE]) -> Self {
        let state: [[u8; 4]; 4] = bytes
            .chunks_exact(4)
            .map(|c| c.try_into().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Self { state }
    }

    /// Load a set of [Block]s from a byte slice and a [Padding] mode
    pub fn load<P>(bytes: &[u8], padding: &P) -> Vec<Self>
    where
        P: Padding<16>,
    {
        padding
            .pad(bytes)
            .into_iter()
            .map(Self::from_bytes)
            .collect()
    }

    /// Dump the inner bytes from the [Block] as continuous byte array
    pub fn dump_bytes(&self) -> [u8; BLOCK_SIZE] {
        let mut dump = [0; 16];

        let mut i = 0;
        for col in self.state {
            for byte in col {
                dump[i] = byte;
                i += 1;
            }
        }

        dump
    }

    /// Substitute bytes
    ///
    /// Substitutes every single byte using the AES [SBOX].
    ///
    /// For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step).
    pub fn sub_bytes(&mut self) {
        for col in &mut self.state {
            *col = util::apply_sbox(*col, SBOX);
        }
    }

    /// Substitute bytes (inverse)
    ///
    /// Substitutes every single byte using the AES [INVERSE_SBOX].
    ///
    /// For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_SubBytes_step).
    pub fn sub_bytes_inv(&mut self) {
        for col in &mut self.state {
            *col = util::apply_sbox(*col, INVERSE_SBOX);
        }
    }

    /// Shift rows
    ///
    /// Cyclically shift the bytes in each row by a certain offset.
    ///
    /// For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step).
    pub fn shift_rows(&mut self) {
        let mut transposed = util::transpose_array2d(&self.state);
        for (i, row) in transposed.iter_mut().enumerate() {
            *row = util::rot_left(*row, i as isize);
        }

        self.state = util::transpose_array2d(&transposed);
    }

    /// Shift rows (inverse)
    ///
    /// Cyclically shift back the bytes in each row by a certain offset.
    ///
    /// For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_ShiftRows_step).
    pub fn shift_rows_inv(&mut self) {
        let mut transposed = util::transpose_array2d(&self.state);
        for (i, row) in transposed.iter_mut().enumerate() {
            *row = util::rot_left(*row, -(i as isize));
        }

        self.state = util::transpose_array2d(&transposed);
    }

    /// Mix columns
    ///
    /// Combine the four bytes of each column using an invertible linear transformation.
    ///
    /// For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step).
    pub fn mix_columns(&mut self) {
        let copy = self.state;

        for c in 0..4 {
            let col = &mut self.state[c];
            let copy = copy[c];

            for r in 0..4 {
                col[r] = match r {
                    0 => GMUL2[copy[0] as usize] ^ GMUL3[copy[1] as usize] ^ copy[2] ^ copy[3],
                    1 => copy[0] ^ GMUL2[copy[1] as usize] ^ GMUL3[copy[2] as usize] ^ copy[3],
                    2 => copy[0] ^ copy[1] ^ GMUL2[copy[2] as usize] ^ GMUL3[copy[3] as usize],
                    3 => GMUL3[copy[0] as usize] ^ copy[1] ^ copy[2] ^ GMUL2[copy[3] as usize],
                    _ => panic!(),
                }
            }
        }
    }

    /// Mix columns (inverse)
    ///
    /// Invert the [mix columns step](Self::mix_columns).
    ///
    /// For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_MixColumns_step).
    pub fn mix_columns_inv(&mut self) {
        let copy = self.state;

        for c in 0..4 {
            let col = &mut self.state[c];
            let copy = copy[c];

            for r in 0..4 {
                col[r] = match r {
                    0 => {
                        GMUL14[copy[0] as usize]
                            ^ GMUL11[copy[1] as usize]
                            ^ GMUL13[copy[2] as usize]
                            ^ GMUL9[copy[3] as usize]
                    }
                    1 => {
                        GMUL9[copy[0] as usize]
                            ^ GMUL14[copy[1] as usize]
                            ^ GMUL11[copy[2] as usize]
                            ^ GMUL13[copy[3] as usize]
                    }
                    2 => {
                        GMUL13[copy[0] as usize]
                            ^ GMUL9[copy[1] as usize]
                            ^ GMUL14[copy[2] as usize]
                            ^ GMUL11[copy[3] as usize]
                    }
                    3 => {
                        GMUL11[copy[0] as usize]
                            ^ GMUL13[copy[1] as usize]
                            ^ GMUL9[copy[2] as usize]
                            ^ GMUL14[copy[3] as usize]
                    }
                    _ => panic!(),
                }
            }
        }
    }

    /// Combine the round's subkey with the state
    ///
    /// For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#The_AddRoundKey).
    pub fn add_round_key(&mut self, round_key: u128) {
        for (i, col) in self.state.iter_mut().enumerate() {
            for (j, byte) in col.iter_mut().enumerate() {
                *byte ^= round_key.to_be_bytes()[i * 4 + j];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_bytes_step() {
        let state = [
            [0x0, 0x1, 0x2, 0x3],
            [0x4, 0x5, 0x6, 0x7],
            [0x8, 0x9, 0xa, 0xb],
            [0xc, 0xd, 0xe, 0xf],
        ];

        let sboxed_state = [
            [0x63, 0x7c, 0x77, 0x7b],
            [0xf2, 0x6b, 0x6f, 0xc5],
            [0x30, 0x01, 0x67, 0x2b],
            [0xfe, 0xd7, 0xab, 0x76],
        ];

        let mut block = Block::new(state);
        block.sub_bytes();

        let expected_block = Block::new(sboxed_state);

        assert_eq!(block, expected_block);
    }

    #[test]
    fn sub_bytes_inv_step() {
        let state = [
            [0x0, 0x1, 0x2, 0x3],
            [0x4, 0x5, 0x6, 0x7],
            [0x8, 0x9, 0xa, 0xb],
            [0xc, 0xd, 0xe, 0xf],
        ];

        let sboxed_state = [
            [0x63, 0x7c, 0x77, 0x7b],
            [0xf2, 0x6b, 0x6f, 0xc5],
            [0x30, 0x01, 0x67, 0x2b],
            [0xfe, 0xd7, 0xab, 0x76],
        ];

        let mut block = Block::new(sboxed_state);
        block.sub_bytes_inv();

        let expected_block = Block::new(state);

        assert_eq!(block, expected_block);
    }

    #[test]
    fn shift_rows_step() {
        let state = [
            [0x0, 0x1, 0x2, 0x3],
            [0x4, 0x5, 0x6, 0x7],
            [0x8, 0x9, 0xa, 0xb],
            [0xc, 0xd, 0xe, 0xf],
        ];

        let shifted_state = [
            [0x0, 0x5, 0xa, 0xf],
            [0x4, 0x9, 0xe, 0x3],
            [0x8, 0xd, 0x2, 0x7],
            [0xc, 0x1, 0x6, 0xb],
        ];

        let mut block = Block::new(state);
        block.shift_rows();

        let expected_block = Block::new(shifted_state);

        assert_eq!(block, expected_block);
    }

    #[test]
    fn shift_rows_inv_step() {
        let state = [
            [0x0, 0x1, 0x2, 0x3],
            [0x4, 0x5, 0x6, 0x7],
            [0x8, 0x9, 0xa, 0xb],
            [0xc, 0xd, 0xe, 0xf],
        ];

        let shifted_state = [
            [0x0, 0x5, 0xa, 0xf],
            [0x4, 0x9, 0xe, 0x3],
            [0x8, 0xd, 0x2, 0x7],
            [0xc, 0x1, 0x6, 0xb],
        ];

        let mut block = Block::new(shifted_state);
        block.shift_rows_inv();

        let expected_block = Block::new(state);

        assert_eq!(block, expected_block);
    }

    #[test]
    fn mix_columns_step() {
        let state = [
            [0xdb, 0x13, 0x53, 0x45],
            [0xf2, 0x0a, 0x22, 0x5c],
            [0xc6, 0xc6, 0xc6, 0xc6],
            [0xd4, 0xd4, 0xd4, 0xd5],
        ];

        // see https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
        let mixed_state = [
            [0x8e, 0x4d, 0xa1, 0xbc],
            [0x9f, 0xdc, 0x58, 0x9d],
            [0xc6, 0xc6, 0xc6, 0xc6],
            [0xd5, 0xd5, 0xd7, 0xd6],
        ];

        let mut block = Block::new(state);
        block.mix_columns();

        let expected_block = Block::new(mixed_state);

        assert_eq!(block, expected_block);
    }

    #[test]
    fn mix_columns_inv_step() {
        let state = [
            [0xdb, 0x13, 0x53, 0x45],
            [0xf2, 0x0a, 0x22, 0x5c],
            [0xc6, 0xc6, 0xc6, 0xc6],
            [0xd4, 0xd4, 0xd4, 0xd5],
        ];

        // see https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
        let mixed_state = [
            [0x8e, 0x4d, 0xa1, 0xbc],
            [0x9f, 0xdc, 0x58, 0x9d],
            [0xc6, 0xc6, 0xc6, 0xc6],
            [0xd5, 0xd5, 0xd7, 0xd6],
        ];

        let mut block = Block::new(mixed_state);
        block.mix_columns_inv();

        let expected_block = Block::new(state);

        assert_eq!(block, expected_block);
    }

    #[test]
    fn add_round_key_step() {
        let state = [
            [0x59, 0x1c, 0xee, 0xa1],
            [0xc2, 0x86, 0x36, 0xd1],
            [0xca, 0xdd, 0xaf, 0x02],
            [0x4a, 0x27, 0xdc, 0xa2],
        ];

        let subkey = 0x62636363626363636263636362636363;

        let added_state = [
            [0x3b, 0x7f, 0x8d, 0xc2],
            [0xa0, 0xe5, 0x55, 0xb2],
            [0xa8, 0xbe, 0xcc, 0x61],
            [0x28, 0x44, 0xbf, 0xc1],
        ];

        let mut block = Block::new(state);
        block.add_round_key(subkey);

        let expected_block = Block::new(added_state);

        assert_eq!(block, expected_block);
    }
}

impl ops::BitXor for Block {
    type Output = Block;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        for (i, col) in self.state.iter_mut().enumerate() {
            for (j, byte) in col.iter_mut().enumerate() {
                *byte ^= rhs.state[i][j];
            }
        }

        self
    }
}

impl ops::BitXorAssign for Block {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (i, col) in self.state.iter_mut().enumerate() {
            for (j, byte) in col.iter_mut().enumerate() {
                *byte ^= rhs.state[i][j];
            }
        }
    }
}

impl From<[u8; 16]> for Block {
    fn from(value: [u8; 16]) -> Self {
        Block::from_bytes(value)
    }
}

impl From<u128> for Block {
    fn from(value: u128) -> Self {
        Block::from_bytes(value.to_be_bytes())
    }
}
