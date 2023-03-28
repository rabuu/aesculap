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
}
