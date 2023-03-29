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
