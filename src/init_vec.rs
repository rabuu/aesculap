use crate::block::Block;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct InitializationVector(Block);

impl InitializationVector {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Block::from_bytes(bytes))
    }

    #[cfg(feature = "rand")]
    pub fn random() -> Self {
        Self(Block::from_bytes(rand::random()))
    }

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
