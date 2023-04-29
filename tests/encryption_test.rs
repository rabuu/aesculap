use aesculap::block::Block;
use aesculap::encryption::encrypt_block;
use aesculap::key::AES128Key;

#[test]
fn single_block_aes128() {
    let encryption_text = "I use Rust btw<3";
    let mut block = Block::from_bytes(encryption_text.as_bytes().try_into().unwrap());

    let key_text = "This is a test12";
    let key = AES128Key::from_bytes(key_text.as_bytes().try_into().unwrap());

    encrypt_block(&mut block, &key);

    let expected_bytes = [
        0x65, 0xdd, 0x99, 0xdf, 0x25, 0xb9, 0xaa, 0x5a, 0x16, 0xb9, 0x40, 0x6f, 0x96, 0xf3, 0x7e,
        0xb1,
    ];

    assert_eq!(block.dump_bytes(), expected_bytes);
}
