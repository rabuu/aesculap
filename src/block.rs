use crate::gmul::*;
use crate::padding::Padding;
use crate::sbox::*;
use crate::util;

pub const BLOCK_SIZE: usize = 16;

#[derive(Debug, PartialEq)]
pub struct Block {
    state: [[u8; 4]; 4],
}

impl Block {
    pub fn new(state: [[u8; 4]; 4]) -> Self {
        Self { state }
    }

    pub fn from_bytes(bytes: [u8; BLOCK_SIZE]) -> Self {
        let state: [[u8; 4]; 4] = bytes
            .chunks_exact(4)
            .map(|c| c.try_into().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Self { state }
    }

    pub fn load(bytes: &[u8], padding: Padding) -> Vec<Self> {
        padding
            .pad(bytes)
            .into_iter()
            .map(Self::from_bytes)
            .collect()
    }

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

    pub fn sub_bytes(&mut self) {
        for col in &mut self.state {
            *col = util::apply_sbox(*col, SBOX);
        }
    }

    pub fn shift_rows(&mut self) {
        let mut transposed = util::transpose_array2d(&self.state);
        for (i, row) in transposed.iter_mut().enumerate() {
            *row = util::rot_left(*row, i as isize);
        }

        self.state = util::transpose_array2d(&transposed);
    }

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
