//! Initialization vector module
//!
//! This module provides a wrapper type for a [Block] that is used as initialization vector (IV).

use crate::block::Block;

/// Initialization vector (IV) wrapper
///
/// This type wraps a [Block] that is used as IV.
///
/// For reference, see the [Wikipedia article](https://en.wikipedia.org/wiki/Initialization_vector)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct InitializationVector(Block);

impl InitializationVector {
    /// Constructor that takes 16 bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Block::from_bytes(bytes))
    }

    /// Construct a random IV
    #[cfg(feature = "rand")]
    pub fn random() -> Self {
        Self(Block::from_bytes(rand::random()))
    }

    /// Get the inner bytes
    pub fn into_bytes(&self) -> [u8; 16] {
        self.0.dump_bytes()
    }
}

impl From<[u8; 16]> for InitializationVector {
    fn from(value: [u8; 16]) -> Self {
        InitializationVector::from_bytes(value)
    }
}

impl From<u128> for InitializationVector {
    fn from(value: u128) -> Self {
        InitializationVector::from_bytes(value.to_be_bytes())
    }
}

impl From<Block> for InitializationVector {
    fn from(value: Block) -> Self {
        InitializationVector(value)
    }
}

impl From<InitializationVector> for Block {
    fn from(val: InitializationVector) -> Self {
        val.0
    }
}
