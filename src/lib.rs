pub mod block;
pub mod decryption;
pub mod encryption;
pub mod init_vec;
pub mod key;
pub mod lookups;
pub mod padding;
pub mod util;

/// AES encryption mode
///
/// Implemented modes:
///
/// - Electronic Code Book (ECB):
///   Each block is encrypted with the same key and algorithm.
///   It is fast and easy but quite insecure and therefore not recommended.
///
/// - Cipher Block Chaining (CBC):
///   An initialization vector (IV) is used and the blocks are chained together.
///   It is generally more secure.
pub enum EncryptionMode {
    ECB,
    CBC(init_vec::InitializationVector),
}
