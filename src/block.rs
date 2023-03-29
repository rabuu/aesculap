use crate::gmul::*;
use crate::sbox::SBOX;

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
            for byte in row {
                *byte = SBOX[*byte as usize];
            }
        }
    }

    pub fn shift_rows(&mut self) {
        for (i, row) in self.bytes.iter_mut().enumerate() {
            shift_row(row, i as isize);
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

fn shift_row(row: &mut [u8; 4], shift: isize) {
    if shift == 0 {
        return;
    }

    let copy = *row;
    for (i, byte) in row.iter_mut().enumerate() {
        let shift_idx = ((i as isize - shift) % 4) as usize;
        *byte = copy[shift_idx];
    }
}
