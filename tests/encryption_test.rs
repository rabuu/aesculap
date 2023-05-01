use aesculap::block::Block;
use aesculap::encryption::encrypt_block;
use aesculap::key::{AES128Key, AES192Key, AES256Key};
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

#[test]
fn single_block_aes128_byte_padding() {
    let encryption_text = b"I use Rust btw";
    let mut blocks = Block::load(encryption_text, Padding::BytePadding(0x69));
    assert_eq!(blocks.len(), 1);

    let key_text = b"0123456789abcdef";
    let key = AES128Key::from_bytes(*key_text);

    encrypt_block(&mut blocks[0], &key);

    let expected_bytes = [
        0x14, 0x18, 0x6d, 0xee, 0x0b, 0x00, 0x7f, 0xf7, 0xb5, 0x6e, 0x8b, 0x01, 0x18, 0x0c, 0x1b,
        0xf0,
    ];

    assert_eq!(blocks[0].dump_bytes(), expected_bytes);
}

#[test]
fn single_block_aes128_zero_padding() {
    let encryption_text = b"I use Rust btw";
    let mut blocks = Block::load(encryption_text, Padding::ZeroPadding);
    assert_eq!(blocks.len(), 1);

    let key_text = b"0123456789abcdef";
    let key = AES128Key::from_bytes(*key_text);

    encrypt_block(&mut blocks[0], &key);

    let expected_bytes = [
        0xed, 0xf0, 0x38, 0x51, 0x31, 0xda, 0x09, 0x7b, 0xc1, 0xc0, 0x41, 0x10, 0x51, 0x21, 0xc2,
        0xa4,
    ];

    assert_eq!(blocks[0].dump_bytes(), expected_bytes);
}

#[test]
fn single_block_aes192_pkcs() {
    let encryption_text = b"I use Rust btw";
    let mut blocks = Block::load(encryption_text, Padding::Pkcs);
    assert_eq!(blocks.len(), 1);

    let key_text = b"0123456789abcdef01234567";
    let key = AES192Key::from_bytes(*key_text);

    encrypt_block(&mut blocks[0], &key);

    let expected_bytes = [
        0xa8, 0x8c, 0xd7, 0xde, 0xd1, 0x99, 0x53, 0x48, 0x16, 0x37, 0x98, 0x69, 0xc3, 0x06, 0x4f,
        0x84,
    ];

    assert_eq!(blocks[0].dump_bytes(), expected_bytes);
}

#[test]
fn single_block_aes256_pkcs() {
    let encryption_text = b"I use Rust btw";
    let mut blocks = Block::load(encryption_text, Padding::Pkcs);
    assert_eq!(blocks.len(), 1);

    let key_text = b"0123456789abcdef0123456789abcdef";
    let key = AES256Key::from_bytes(*key_text);

    encrypt_block(&mut blocks[0], &key);

    let expected_bytes = [
        0x48, 0xba, 0xc4, 0x2d, 0xfd, 0x34, 0x5d, 0x0a, 0xa9, 0x17, 0x58, 0x0b, 0xc9, 0x35, 0x3e,
        0xb4,
    ];

    assert_eq!(blocks[0].dump_bytes(), expected_bytes);
}

#[test]
fn multiple_blocks_aes128_pkcs() {
    let encryption_text = b"felis eget nunc lobortis mattis aliquam faucibus purus in massa tempor nec feugiat nisl pretium fusce";
    let mut blocks = Block::load(encryption_text, Padding::Pkcs);

    let key_text = b"0123456789abcdef";
    let key = AES128Key::from_bytes(*key_text);

    for block in &mut blocks {
        encrypt_block(block, &key);
    }

    let encrypted_bytes: Vec<u8> = blocks
        .iter_mut()
        .map(|b| b.dump_bytes())
        .flatten()
        .collect();

    let expected_bytes = vec![
        0xea, 0x90, 0xe6, 0xe1, 0xdd, 0xa8, 0x44, 0xd5, 0x24, 0x70, 0x7e, 0x2a, 0x1e, 0x5e, 0xd7,
        0x43, 0x69, 0xea, 0xa7, 0x4b, 0xe7, 0xef, 0x6d, 0x0e, 0x5a, 0xb0, 0xf9, 0xab, 0x62, 0x76,
        0x41, 0x3e, 0x4e, 0x36, 0xbf, 0xdb, 0x55, 0x3d, 0xae, 0xf3, 0x73, 0x70, 0x72, 0xda, 0x56,
        0x0b, 0xb8, 0x42, 0x15, 0xe0, 0xec, 0xef, 0x1a, 0xbe, 0xba, 0x33, 0x60, 0xe9, 0xd4, 0x6f,
        0x3c, 0x3e, 0xe7, 0xea, 0xe2, 0xec, 0x4c, 0x92, 0xf5, 0xfe, 0xfd, 0x1d, 0x63, 0x8a, 0x8a,
        0xb4, 0xf8, 0x19, 0x31, 0x29, 0x65, 0x46, 0xb7, 0x38, 0x24, 0x7e, 0x97, 0x6a, 0xa0, 0xf4,
        0xae, 0xd3, 0xf9, 0x73, 0xe6, 0xc1, 0x91, 0x82, 0xfe, 0x15, 0x00, 0x3a, 0xce, 0x31, 0x30,
        0x73, 0x0c, 0x05, 0x9a, 0x6c, 0x1e, 0x0a,
    ];

    assert_eq!(encrypted_bytes, expected_bytes);
}
