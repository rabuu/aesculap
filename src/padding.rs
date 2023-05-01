#[derive(Debug)]
pub enum Padding {
    Pkcs,
    BytePadding(u8),
    ZeroPadding,
}

impl Padding {
    pub fn pad<const B: usize>(&self, bytes: &[u8]) -> Vec<[u8; B]> {
        use Padding::*;

        let mut blocks: Vec<[u8; B]> = bytes
            .chunks_exact(B)
            .map(|c| c.try_into().unwrap())
            .collect();

        let remainder = bytes.chunks_exact(B).remainder();

        match *self {
            Pkcs => pkcs(&mut blocks, remainder),
            BytePadding(byte) => pad_with_byte(&mut blocks, remainder, byte),
            ZeroPadding => pad_with_byte(&mut blocks, remainder, 0),
        }

        blocks
    }
}

fn pkcs<const B: usize>(blocks: &mut Vec<[u8; B]>, remainder: &[u8]) {
    let missing_bytes = B - remainder.len();
    let last_block: [u8; B] = remainder
        .iter()
        .chain(vec![missing_bytes as u8; missing_bytes].iter())
        .map(|&b| b)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    blocks.push(last_block);
}

fn pad_with_byte<const B: usize>(blocks: &mut Vec<[u8; B]>, remainder: &[u8], byte: u8) {
    if remainder.is_empty() {
        return;
    }

    let missing_bytes = B - remainder.len();
    let last_block: [u8; B] = remainder
        .iter()
        .chain(vec![byte; missing_bytes].iter())
        .map(|&b| b)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    blocks.push(last_block);
}
