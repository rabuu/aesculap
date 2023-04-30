mod aes;
mod generic;

pub use generic::GenericKey;

pub use aes::{AES128Key, AES192Key, AES256Key};

pub trait Key<const R: usize> {
    fn round_keys(&self) -> [Subkey; R];
}

type Word = u32;
type Subkey = u128;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes128_key_schedule() {
        let original_key = b"0123456789abcdef";
        let key = AES128Key::from_bytes(*original_key);

        let round_keys = key.generate_round_keys();

        let expected_round_keys = [
            0x30313233343536373839616263646566,
            0x727c01c8464937ff7e70569d1d1433fb,
            0x8abf0e6cccf63993b2866f0eaf925cf5,
            0xc1f5e8150d03d186bf85be881017e27d,
            0x396d17df346ec6598beb78d19bfc9aac,
            0x99d586cbadbb409226503843bdaca2ef,
            0x28ef59b185541923a30421601ea8838f,
            0xaa032ac32f5733e08c53128092fb910f,
            0x25825c8c0ad56f6c86867dec147dece3,
            0xc14c4d76cb99221a4d1f5ff65962b315,
            0x5d2114bd96b836a7dba7695182c5da44,
        ];

        assert_eq!(round_keys, expected_round_keys);
    }
}
