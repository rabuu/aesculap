pub fn rot_left(mut word: [u8; 4], shift: isize) -> [u8; 4] {
    if shift == 0 {
        return word;
    }

    let copy = word.clone();
    for (i, byte) in word.iter_mut().enumerate() {
        let shift_idx = (i as isize + shift).rem_euclid(4) as usize;
        *byte = copy[shift_idx];
    }

    word
}

pub fn apply_sbox(mut word: [u8; 4], sbox: [u8; 256]) -> [u8; 4] {
    for byte in &mut word {
        *byte = sbox[*byte as usize];
    }

    word
}

pub fn bytes_as_u32(bytes: [u8; 4]) -> u32 {
    (bytes[3] as u32)
        | ((bytes[2] as u32) << 8)
        | ((bytes[1] as u32) << 16)
        | ((bytes[0] as u32) << 24)
}
