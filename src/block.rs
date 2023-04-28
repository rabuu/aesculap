use crate::gmul::*;
use crate::sbox::*;
use crate::util;

#[derive(Debug)]
pub struct Block {
    bytes: [[u8; 4]; 4],
}

impl Block {
    pub fn new(bytes: [[u8; 4]; 4]) -> Self {
        Self { bytes }
    }

    pub fn sub_bytes(&mut self) {
        for row in &mut self.bytes {
            *row = util::apply_sbox(*row, SBOX);
        }
    }

    pub fn shift_rows(&mut self) {
        for (i, row) in self.bytes.iter_mut().enumerate() {
            *row = util::rot_left(*row, i as isize);
        }
    }

    pub fn mix_columns(&mut self) {
        let copy = self.bytes;

        for c in 0..4 {
            for r in 0..4 {
                self.bytes[r][c] = match r {
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
}
