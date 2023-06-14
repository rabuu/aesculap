//! Lookups module
//!
//! This module provides lookup tables for AES S-boxes and the Galois multiplication needed for the [mix columns step](crate::block::Block::mix_columns).

pub mod gmul;
pub mod sbox;
