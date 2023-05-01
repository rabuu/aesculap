use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(author, version)]
#[command(about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Encrypt data
    #[command(alias = "en")]
    Encrypt {
        /// The key must have a size of 128, 192 or 256 bits (16, 24 or 32 bytes)
        #[arg(long, short)]
        key_file: PathBuf,

        #[command(flatten)]
        mode: Mode,

        /// Padding is required to divide the data into even sized blocks
        #[arg(long, short)]
        #[arg(value_enum, default_value_t = Padding::Pkcs7)]
        padding: Padding,

        #[command(flatten)]
        iv: Option<Iv>,

        #[command(flatten)]
        input: Input,

        #[command(flatten)]
        output: Output,
    },

    /// Decrypt data
    #[command(alias = "de")]
    Decrypt {
        /// The key must have a size of 128, 192 or 256 bits (16, 24 or 32 bytes)
        #[arg(long, short)]
        key_file: PathBuf,

        #[command(flatten)]
        mode: Mode,

        #[arg(long, short)]
        #[arg(value_enum, default_value_t = Padding::Pkcs7)]
        padding: Padding,

        /// In CBC mode an IV with a size of 128 bits (16 bytes) is required
        #[arg(long)]
        #[arg(group = "iv")]
        iv_file: Option<PathBuf>,

        #[command(flatten)]
        input: Input,

        #[command(flatten)]
        output: Output,
    },
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct Mode {
    /// Cipher Block Chaining mode
    ///
    /// An initialization vector (IV) is used and the blocks are chained together. It is generally more secure.
    #[arg(long)]
    #[arg(requires = "iv")]
    cbc: bool,

    /// Electronic Code Book mode (not recommended)
    ///
    /// Each block is encrypted with the same key and algorithm. It is fast and easy but quite insecure.
    #[arg(long)]
    #[arg(conflicts_with = "iv")]
    ecb: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Debug)]
enum Padding {
    /// Padding is done according to PKCS #7 (recommended)
    Pkcs7,

    /// The blocks are filled with zeroes
    Zero,

    /// The data is not padded (may fail)
    None,
}

#[derive(Args, Debug)]
#[group(id = "iv")]
#[group(multiple = false)]
struct Iv {
    /// In CBC mode an IV with a size of 128 bits (16 bytes) is required
    #[arg(long)]
    iv_file: Option<PathBuf>,

    /// Generate a random IV and write it to a file
    #[arg(long)]
    random_iv: Option<PathBuf>,
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct Input {
    /// Read the input from a file
    #[arg(long, short)]
    input_file: Option<PathBuf>,

    /// Read the input from STDIN
    #[arg(long)]
    stdin: bool,
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct Output {
    /// Write the output to a file
    #[arg(long, short)]
    output_file: Option<PathBuf>,

    /// Write the output to STDOUT
    #[arg(long)]
    stdout: bool,
}

fn main() {
    let cli = Cli::parse();
    dbg!(cli);
}
