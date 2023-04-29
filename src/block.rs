use crate::gmul::*;
use crate::sbox::*;
use crate::util;

#[derive(Debug, PartialEq)]
pub struct Block {
    state: [[u8; 4]; 4],
}

impl Block {
    pub fn new(state: [[u8; 4]; 4]) -> Self {
        Self { state }
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        let state: [[u8; 4]; 4] = bytes
            .chunks_exact(4)
            .map(|c| c.try_into().unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        Self { state }
    }

    pub fn dump_bytes(&self) -> [u8; 16] {
        let mut dump = [0; 16];

        let mut i = 0;
        for row in self.state {
            for byte in row {
                dump[i] = byte;
                i += 1;
            }
        }

        dump
    }

    pub fn sub_bytes(&mut self) {
        for row in &mut self.state {
            *row = util::apply_sbox(*row, SBOX);
        }
    }

    pub fn shift_rows(&mut self) {
        for (i, row) in self.state.iter_mut().enumerate() {
            *row = util::rot_left(*row, i as isize);
        }
    }

    pub fn mix_columns(&mut self) {
        let copy = self.state;

        for c in 0..4 {
            for r in 0..4 {
                self.state[r][c] = match r {
                    0 => {
                        GMUL2[copy[0][c] as usize]
                            ^ GMUL3[copy[1][c] as usize]
                            ^ copy[2][c]
                            ^ copy[3][c]
                    }
                    1 => {
                        copy[0][c]
                            ^ GMUL2[copy[1][c] as usize]
                            ^ GMUL3[copy[2][c] as usize]
                            ^ copy[3][c]
                    }
                    2 => {
                        copy[0][c]
                            ^ copy[1][c]
                            ^ GMUL2[copy[2][c] as usize]
                            ^ GMUL3[copy[3][c] as usize]
                    }
                    3 => {
                        GMUL3[copy[0][c] as usize]
                            ^ copy[1][c]
                            ^ copy[2][c]
                            ^ GMUL2[copy[3][c] as usize]
                    }
                    _ => panic!(),
                }
            }
        }
    }

    pub fn add_round_key(&mut self, round_key: u128) {
        for (i, row) in self.state.iter_mut().enumerate() {
            for (j, byte) in row.iter_mut().enumerate() {
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
            [0x0, 0x1, 0x2, 0x3],
            [0x5, 0x6, 0x7, 0x4],
            [0xa, 0xb, 0x8, 0x9],
            [0xf, 0xc, 0xd, 0xe],
        ];

        let mut block = Block::new(state);
        block.shift_rows();

        let expected_block = Block::new(shifted_state);

        assert_eq!(block, expected_block);
    }

    #[test]
    fn mix_columns_step() {
        let state = [
            [0xdb, 0xf2, 0xc6, 0xd4],
            [0x13, 0x0a, 0xc6, 0xd4],
            [0x53, 0x22, 0xc6, 0xd4],
            [0x45, 0x5c, 0xc6, 0xd5],
        ];

        // see https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
        let mixed_state = [
            [0x8e, 0x9f, 0xc6, 0xd5],
            [0x4d, 0xdc, 0xc6, 0xd5],
            [0xa1, 0x58, 0xc6, 0xd7],
            [0xbc, 0x9d, 0xc6, 0xd6],
        ];

        let mut block = Block::new(state);
        block.mix_columns();

        let expected_block = Block::new(mixed_state);

        assert_eq!(block, expected_block);
    }
}
