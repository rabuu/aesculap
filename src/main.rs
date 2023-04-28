use aesculap::{block::Block, key::AES128Key};

fn main() {
    let key = AES128Key::new(
        "This is a test12"
            .to_string()
            .into_bytes()
            .chunks_exact(4)
            .map(|c| {
                c.into_iter()
                    .enumerate()
                    .map(|(i, &x)| (x as u32) << (3 - i) * 8)
                    .sum()
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    );

    let bytes: [u8; 16] = "I use Rust btw<3".as_bytes().try_into().unwrap();
    let mut block = Block::from_bytes(bytes);

    aesculap::encryption::encrypt_block(&mut block, key);

    print!("{:#x?}", block);
    // FIXME: This is not working properly
}
