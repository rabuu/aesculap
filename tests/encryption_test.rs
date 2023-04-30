use aesculap::block::Block;
use aesculap::encryption::encrypt_block;
use aesculap::key::AES128Key;
use aesculap::padding::Padding;

#[test]
fn single_block_aes128_pkcs() {
    let encryption_text = b"I use Rust btw";
    let mut blocks = Block::load(encryption_text, Padding::Pkcs);
    assert_eq!(blocks.len(), 1);

    let key_text = b"0123456789abcdef";
    let key = AES128Key::from_bytes(*key_text);

    encrypt_block(&mut blocks[0], &key);

    let expected_bytes = [
        0x1b, 0xf1, 0xdb, 0x98, 0x04, 0x1a, 0x4f, 0x2e, 0x2d, 0xd2, 0x06, 0xf8, 0xb6, 0x07, 0xe1,
        0x79,
    ];

    assert_eq!(blocks[0].dump_bytes(), expected_bytes);
}
