use crate::gmul::*;
use crate::sbox::*;
use crate::util;

#[derive(Debug)]
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
