fn main() {
    let mut block = aesculap::block::Block::new([[0xd4; 4], [0x32; 4], [0xf4; 4], [0xae; 4]]);
    block.mix_columns();

    println!("{:#x?}", block);
}
