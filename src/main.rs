use aesculap::{block::Block, key::AES128Key};

fn main() {
    let key = AES128Key::from_bytes("This is a test12".as_bytes().try_into().unwrap());

    let bytes: [u8; 16] = "I use Rust btw<3".as_bytes().try_into().unwrap();
    let mut block = Block::from_bytes(bytes);

    aesculap::encryption::encrypt_block(&mut block, &key);

    print!("{:#x?}", block);
    // FIXME: This is not working properly
}
