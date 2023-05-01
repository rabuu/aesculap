pub mod block;
pub mod decryption;
pub mod encryption;
pub mod init_vec;
pub mod key;
pub mod lookups;
pub mod padding;
pub mod util;

pub enum EncryptionMode {
    ECB,
    CBC(init_vec::InitializationVector),
}
