pub mod block;
pub mod decryption;
pub mod encryption;
pub mod key;
pub mod lookups;
pub mod padding;

mod iv;
mod util;

pub use iv::InitializationVector;

/// AES encryption mode
///
/// Implemented modes:
///
/// - Electronic Code Book (ECB):
///   Each block is encrypted with the same key and algorithm.
///   It is fast and easy but quite insecure and therefore not recommended.
///
/// - Cipher Block Chaining (CBC):
///   An [initialization vector (IV)](InitializationVector) is used and the blocks are chained together.
///   It is generally more secure.
pub enum EncryptionMode {
    ECB,
    CBC(InitializationVector),
}
