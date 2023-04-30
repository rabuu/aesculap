#[derive(Debug)]
pub enum Padding {
    Pkcs,
}

impl Padding {
    pub fn pad<const B: usize>(&self, bytes: &[u8]) -> Vec<[u8; B]> {
        use Padding::*;

        match *self {
            Pkcs => pkcs(bytes),
        }
    }
}

fn pkcs<const B: usize>(bytes: &[u8]) -> Vec<[u8; B]> {
    let mut blocks: Vec<[u8; B]> = bytes
        .chunks_exact(B)
        .map(|c| c.try_into().unwrap())
        .collect();

    let remainder = bytes.chunks_exact(B).remainder();
    let missing_bytes = B - remainder.len();
    let last_block: [u8; B] = remainder
        .iter()
        .chain(vec![missing_bytes as u8; missing_bytes].iter())
        .map(|&b| b)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    blocks.push(last_block);

    blocks
}
