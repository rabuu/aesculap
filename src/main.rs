use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    process,
};

use clap::{Args, Parser, Subcommand, ValueEnum};

use aesculap::{
    decryption::decrypt_bytes,
    encryption::encrypt_bytes,
    init_vec::InitializationVector,
    key::{AES128Key, AES192Key, AES256Key, Key},
    padding::{Padding as PaddingMode, Pkcs7Padding, ZeroPadding},
    EncryptionMode,
};

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
            let mut key_file = File::open(&key_file).unwrap_or_else(|err| {
                eprintln!("Error: {:?}: {}", key_file, err);
                process::exit(1);
            });

            let mut key_bytes: Vec<u8> = Vec::new();
            key_file.read_to_end(&mut key_bytes).unwrap();

            let mode: EncryptionMode = if mode.ecb {
                EncryptionMode::ECB
            } else if mode.cbc {
                let iv = iv.expect("CBC mode but no IV");
                if let Some(iv_file) = iv.iv_file {
                    let mut iv_file = File::open(&iv_file).unwrap_or_else(|err| {
                        eprintln!("Error: {:?}: {}", iv_file, err);
                        process::exit(1);
                    });

                    let mut buf = [0; 16];
                    iv_file.read_exact(&mut buf).unwrap();

                    let iv = InitializationVector::from_bytes(buf);

                    EncryptionMode::CBC(iv)
                } else if let Some(iv_file) = iv.random_iv {
                    if cfg!(feature = "rand") {
                        let mut iv_file = File::create(&iv_file).unwrap_or_else(|err| {
                            eprintln!("Error: {:?}: {}", iv_file, err);
                            process::exit(1);
                        });

                        let random_iv = InitializationVector::random();
                        iv_file.write_all(&random_iv.into_bytes()).unwrap();

                        EncryptionMode::CBC(random_iv)
                    } else {
                        panic!("Feature 'rand' not enabled");
                    }
                } else {
                    panic!("IV neither given nor random");
                }
            } else {
                panic!("Mode neither ECB nor CBC");
            };

            let mut plaintext: Vec<u8> = Vec::new();
            if let Some(input_file) = input.input_file {
                let mut input_file = File::open(&input_file).unwrap_or_else(|err| {
                    eprintln!("Error: {:?}: {}", input_file, err);
                    process::exit(1);
                });

                input_file.read_to_end(&mut plaintext).unwrap();
            } else if input.stdin {
                todo!()
            } else {
                panic!("Neither input file nor STDIN");
            };

            if padding == Padding::None && plaintext.len() % 16 != 0 {
                eprintln!(
                    "Error: Without padding the number of input bytes has to be divisible by 16"
                );
                process::exit(1);
            }

            let mut output: Box<dyn Write> = if let Some(output_file) = output.output_file {
                let output_file = File::create(&output_file).unwrap_or_else(|err| {
                    eprintln!("Error: {:?}: {}", output_file, err);
                    process::exit(1);
                });

                Box::new(output_file)
            } else if output.stdout {
                todo!()
            } else {
                panic!("Neither output file nor STDOUT");
            };

            let output_bytes = match key_bytes.len() {
                16 => {
                    let key = AES128Key::from_bytes(key_bytes.try_into().unwrap());
                    match padding {
                        Padding::Pkcs7 => encrypt_bytes(&plaintext, &key, &Pkcs7Padding, mode),
                        Padding::Zero | Padding::None => {
                            encrypt_bytes(&plaintext, &key, &ZeroPadding, mode)
                        }
                    }
                }
                24 => {
                    let key = AES192Key::from_bytes(key_bytes.try_into().unwrap());
                    match padding {
                        Padding::Pkcs7 => encrypt_bytes(&plaintext, &key, &Pkcs7Padding, mode),
                        Padding::Zero | Padding::None => {
                            encrypt_bytes(&plaintext, &key, &ZeroPadding, mode)
                        }
                    }
                }
                32 => {
                    let key = AES256Key::from_bytes(key_bytes.try_into().unwrap());
                    match padding {
                        Padding::Pkcs7 => encrypt_bytes(&plaintext, &key, &Pkcs7Padding, mode),
                        Padding::Zero | Padding::None => {
                            encrypt_bytes(&plaintext, &key, &ZeroPadding, mode)
                        }
                    }
                }
                _ => {
                    eprintln!("Error: Key file must have a size of 128, 192 or 256 bits (16, 24, or 32 bytes)");
                    process::exit(1);
                }
            };

            output.write_all(&output_bytes).unwrap();
        }
        Command::Decrypt {
            key_file,
            mode,
            padding,
            iv_file,
            input,
            output,
        } => {
            let mut key_file = File::open(&key_file).unwrap_or_else(|err| {
                eprintln!("Error: {:?}: {}", key_file, err);
                process::exit(1);
            });

            let mut key_bytes: Vec<u8> = Vec::new();
            key_file.read_to_end(&mut key_bytes).unwrap();

            let mode: EncryptionMode = if mode.ecb {
                EncryptionMode::ECB
            } else if mode.cbc {
                if let Some(iv_file) = iv_file {
                    let mut iv_file = File::open(&iv_file).unwrap_or_else(|err| {
                        eprintln!("Error: {:?}: {}", iv_file, err);
                        process::exit(1);
                    });

                    let mut buf = [0; 16];
                    iv_file.read_exact(&mut buf).unwrap();

                    let iv = InitializationVector::from_bytes(buf);

                    EncryptionMode::CBC(iv)
                } else {
                    panic!("CBC mode but no iv_file");
                }
            } else {
                panic!("Mode neither ECB nor CBC");
            };

            let mut ciphertext: Vec<u8> = Vec::new();
            if let Some(input_file) = input.input_file {
                let mut input_file = File::open(&input_file).unwrap_or_else(|err| {
                    eprintln!("Error: {:?}: {}", input_file, err);
                    process::exit(1);
                });

                input_file.read_to_end(&mut ciphertext).unwrap();
            } else if input.stdin {
                todo!()
            } else {
                panic!("Neither input file nor STDIN");
            };

            let mut output: Box<dyn Write> = if let Some(output_file) = output.output_file {
                let output_file = File::create(&output_file).unwrap_or_else(|err| {
                    eprintln!("Error: {:?}: {}", output_file, err);
                    process::exit(1);
                });

                Box::new(output_file)
            } else if output.stdout {
                todo!()
            } else {
                panic!("Neither output file nor STDOUT");
            };

            let output_bytes = match key_bytes.len() {
                16 => {
                    let key = AES128Key::from_bytes(key_bytes.try_into().unwrap());
                    match padding {
                        Padding::Pkcs7 => {
                            decrypt_bytes(&ciphertext, &key, Some(Pkcs7Padding), mode).unwrap()
                        }
                        Padding::Zero => {
                            decrypt_bytes(&ciphertext, &key, Some(ZeroPadding), mode).unwrap()
                        }
                        Padding::None => {
                            decrypt_bytes(&ciphertext, &key, None::<ZeroPadding>, mode).unwrap()
                        }
                    }
                }
                24 => {
                    let key = AES192Key::from_bytes(key_bytes.try_into().unwrap());
                    match padding {
                        Padding::Pkcs7 => {
                            decrypt_bytes(&ciphertext, &key, Some(Pkcs7Padding), mode).unwrap()
                        }
                        Padding::Zero => {
                            decrypt_bytes(&ciphertext, &key, Some(ZeroPadding), mode).unwrap()
                        }
                        Padding::None => {
                            decrypt_bytes(&ciphertext, &key, None::<ZeroPadding>, mode).unwrap()
                        }
                    }
                }
                32 => {
                    let key = AES256Key::from_bytes(key_bytes.try_into().unwrap());
                    match padding {
                        Padding::Pkcs7 => {
                            decrypt_bytes(&ciphertext, &key, Some(Pkcs7Padding), mode).unwrap()
                        }
                        Padding::Zero => {
                            decrypt_bytes(&ciphertext, &key, Some(ZeroPadding), mode).unwrap()
                        }
                        Padding::None => {
                            decrypt_bytes(&ciphertext, &key, None::<ZeroPadding>, mode).unwrap()
                        }
                    }
                }
                _ => {
                    eprintln!("Error: Key file must have a size of 128, 192 or 256 bits (16, 24, or 32 bytes)");
                    process::exit(1);
                }
            };

            output.write_all(&output_bytes).unwrap();
        }
    }
}
