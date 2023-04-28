use aesculap::key::AES128Key;

fn main() {
    println!("{:x?}", aesculap::sbox::SBOX[0x63]);
    println!("{:x?}", aesculap::sbox::SBOX[0x62]);
    let key = AES128Key::new([0, 0, 0, 0]);
    println!("{:#034x?}", key.generate_round_keys());
}
