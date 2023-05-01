use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    process,
};

use clap::{Args, Parser, Subcommand, ValueEnum};

use aesculap::{init_vec::InitializationVector, EncryptionMode};

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
    #[cfg(feature = "rand")]
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

    match cli.cmd {
        Command::Encrypt {
            key_file,
            mode,
            padding,
            iv,
            input,
            output,
        } => {
            let key_file = File::open(&key_file).unwrap_or_else(|err| {
                eprintln!("Error: {}", err);
                process::exit(1);
            });

            let encryption_mode: EncryptionMode = if mode.ecb {
                EncryptionMode::ECB
            } else if mode.cbc {
                let iv = iv.expect("CBC mode but no IV");
                let iv = if let Some(iv_file) = iv.iv_file {
                    let iv_file = File::open(&iv_file).unwrap_or_else(|err| {
                        eprintln!("Error: {}", err);
                        process::exit(1);
                    });

                    let mut buf = [0; 16];
                    iv_file.read_exact(&mut buf);

                    let iv = InitializationVector::from_bytes(buf);

                    EncryptionMode::CBC(iv)
                } else if let Some(iv_file) = iv.random_iv {
                    if cfg!(feature = "rand") {
                        let iv_file = File::create(&iv_file).unwrap_or_else(|err| {
                            eprintln!("Error: {}", err);
                            process::exit(1);
                        });

                        let random_iv = InitializationVector::random();
                        iv_file.write_all(&random_iv.into_bytes());

                        EncryptionMode::CBC(random_iv)
                    } else {
                        panic!("Feature 'rand' not enabled");
                    }
                } else {
                    panic!("IV neither given nor random");
                };
            } else {
                panic!("Mode neither ECB nor CBC");
            };

            match key_file.metadata().unwrap().len() {
                16 => (),
                24 => (),
                32 => (),
                _ => (),
            };
        }
        Command::Decrypt {
            key_file,
            mode,
            padding,
            iv_file,
            input,
            output,
        } => todo!(),
    }
}
