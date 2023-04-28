use aesculap::key::AES128Key;

fn main() {
    println!("{:?}", aesculap::util::rot_left([1, 2, 3, 4, 5], 2));
    let key = AES128Key::new([0, 0, 0, 0]);
    println!("{:#034x?}", key.generate_round_keys());
}
