//! Padding module
//!
//! This module provides types to pad bytes in different ways to prepare them for encryption.
//! A [Padding] trait defines a common interface.
//!
//! Possible padding modes:
//! - [PKCS7](Pkcs7Padding) (recommended)
//! - [Byte padding](BytePadding)
//! - [Zeroes](ZeroPadding)

/// A trait that defines a common padding interface
pub trait Padding<const B: usize> {
    /// Pad the given bytes so they fit in equal-sized chunks
    fn pad(&self, bytes: &[u8]) -> Vec<[u8; B]>;

    /// Undo the padding
    fn unpad(&self, padded_bytes: &[[u8; B]]) -> Vec<u8>;
}

/// PKCS #7 padding standard
///
/// For reference, see the [IBM specification](https://www.ibm.com/docs/en/zos/2.1.0?topic=rules-pkcs-padding-method)
#[derive(Debug)]
pub struct Pkcs7Padding;

impl<const B: usize> Padding<B> for Pkcs7Padding {
    fn pad(&self, bytes: &[u8]) -> Vec<[u8; B]> {
        let mut chunks: Vec<[u8; B]> = bytes
            .chunks_exact(B)
            .map(|c| c.try_into().unwrap())
            .collect();

        let remainder = bytes.chunks_exact(B).remainder();
        let missing_bytes = B - remainder.len();

        let last_chunk: [u8; B] = remainder
            .iter()
            .chain(vec![missing_bytes as u8; missing_bytes].iter())
            .copied()
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        chunks.push(last_chunk);

        chunks
    }

    fn unpad(&self, padded_bytes: &[[u8; B]]) -> Vec<u8> {
        if padded_bytes.is_empty() {
            return vec![];
        }

        let mut bytes: Vec<u8> = padded_bytes.iter().flatten().copied().collect();
        let last_byte = *bytes.last().unwrap();
        bytes.truncate(bytes.len() - last_byte as usize);

        bytes
    }
}

/// Fill empty chunk space with a given byte
#[derive(Debug)]
pub struct BytePadding(pub u8);

impl<const B: usize> Padding<B> for BytePadding {
    fn pad(&self, bytes: &[u8]) -> Vec<[u8; B]> {
        let missing_bytes = bytes.len() % B;

        [bytes, &vec![self.0; missing_bytes]]
            .concat()
            .chunks_exact(B)
            .map(|c| c.try_into().unwrap())
            .collect()
    }

    fn unpad(&self, padded_bytes: &[[u8; B]]) -> Vec<u8> {
        if padded_bytes.is_empty() {
            return vec![];
        }

        let mut bytes: Vec<u8> = padded_bytes.iter().flatten().copied().collect();

        while *bytes.last().unwrap() == self.0 {
            bytes.pop();
        }

        bytes
    }
}

/// Fill empty chunk space with zeroes
#[derive(Debug)]
pub struct ZeroPadding;

impl<const B: usize> Padding<B> for ZeroPadding {
    fn pad(&self, bytes: &[u8]) -> Vec<[u8; B]> {
        let missing_bytes = bytes.len() % B;

        [bytes, &vec![0; missing_bytes]]
            .concat()
            .chunks_exact(B)
            .map(|c| c.try_into().unwrap())
            .collect()
    }

    fn unpad(&self, padded_bytes: &[[u8; B]]) -> Vec<u8> {
        if padded_bytes.is_empty() {
            return vec![];
        }

        let mut bytes: Vec<u8> = padded_bytes.iter().flatten().copied().collect();

        while *bytes.last().unwrap() == 0 {
            bytes.pop();
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_pad() {
        let bytes = [
            0xf1, 0x4a, 0xdb, 0xda, 0x01, 0x9d, 0x6d, 0xb7, 0xef, 0xd9, 0x15, 0x46, 0xe3, 0xff,
            0x84, 0x44, 0x9b, 0xcb,
        ];

        let expected = vec![
            [
                0xf1, 0x4a, 0xdb, 0xda, 0x01, 0x9d, 0x6d, 0xb7, 0xef, 0xd9, 0x15, 0x46, 0xe3, 0xff,
                0x84, 0x44,
            ],
            [
                0x9b, 0xcb, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
                0x0e, 0x0e,
            ],
        ];

        let padding = Pkcs7Padding;
        let padded_bytes: Vec<[u8; 16]> = padding.pad(&bytes);

        assert_eq!(padded_bytes, expected);
    }

    #[test]
    fn pkcs7_unpad() {
        let padded = vec![
            [
                0xf1, 0x4a, 0xdb, 0xda, 0x01, 0x9d, 0x6d, 0xb7, 0xef, 0xd9, 0x15, 0x46, 0xe3, 0xff,
                0x84, 0x44,
            ],
            [
                0x9b, 0xcb, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
                0x0e, 0x0e,
            ],
        ];

        let expected = vec![
            0xf1, 0x4a, 0xdb, 0xda, 0x01, 0x9d, 0x6d, 0xb7, 0xef, 0xd9, 0x15, 0x46, 0xe3, 0xff,
            0x84, 0x44, 0x9b, 0xcb,
        ];

        let padding = Pkcs7Padding;
        let unpadded = padding.unpad(&padded);

        assert_eq!(unpadded, expected);
    }
}
