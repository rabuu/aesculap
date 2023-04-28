pub fn rot_left<const N: usize>(mut bytes: [u8; N], shift: isize) -> [u8; N] {
    if shift == 0 {
        return bytes;
    }

    let copy = bytes.clone();
    for (i, byte) in bytes.iter_mut().enumerate() {
        let shift_idx = (i as isize + shift).rem_euclid(N as isize) as usize;
        *byte = copy[shift_idx];
    }

    bytes
}

pub fn apply_sbox<const N: usize>(mut bytes: [u8; N], sbox: [u8; 256]) -> [u8; N] {
    for byte in &mut bytes {
        *byte = sbox[*byte as usize];
    }

    bytes
}

pub fn bytes_as_u32(bytes: [u8; 4]) -> u32 {
    (bytes[3] as u32)
        | ((bytes[2] as u32) << 8)
        | ((bytes[1] as u32) << 16)
        | ((bytes[0] as u32) << 24)
}
