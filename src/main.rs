use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::process;

use clap::{Args, Parser, Subcommand, ValueEnum};

use aesculap::key::{AES128Key, AES192Key, AES256Key};
use aesculap::padding::{Pkcs7Padding, ZeroPadding};
use aesculap::EncryptionMode;
use aesculap::InitializationVector;

use aesculap::decryption::decrypt_bytes;
use aesculap::encryption::encrypt_bytes;

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
        #[arg(value_enum, default_value_t = PaddingOption::Pkcs7)]
        padding: PaddingOption,

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
        #[arg(value_enum, default_value_t = PaddingOption::Pkcs7)]
        padding: PaddingOption,

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
enum PaddingOption {
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
    #[arg(value_name = "IV_FILE")]
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
            let key = read_key(key_file).unwrap();

            let mode: EncryptionMode = match (mode.ecb, mode.cbc) {
                (true, false) => EncryptionMode::ECB,
                (false, true) => {
                    let iv = iv.unwrap();

                    if let Some(iv_file) = iv.iv_file {
                        let iv = read_iv(iv_file).unwrap();
                        let iv = InitializationVector::from_bytes(iv);

                        EncryptionMode::CBC(iv)
                    } else if let Some(iv_file) = iv.random_iv {
                        if cfg!(feature = "rand") {
                            let iv = InitializationVector::random();
                            write_iv(iv_file, &iv).unwrap();

                            EncryptionMode::CBC(iv)
                        } else {
                            panic!("Feature 'rand' not enabled");
                        }
                    } else {
                        panic!("Unvalid IV state");
                    }
                }
                _ => panic!("Unvalid encryption mode"),
            };

            let mut plaintext: Vec<u8> = Vec::new();
            if let Some(input_file) = input.input_file {
                let input_file = File::open(&input_file).unwrap_or_else(|err| {
                    eprintln!("Error: {:?}: {}", input_file, err);
                    process::exit(1);
                });

                let mut reader = BufReader::new(input_file);
                reader.read_to_end(&mut plaintext).unwrap();
            } else if input.stdin {
                todo!()
            } else {
                panic!("Neither input file nor STDIN");
            };

            if padding == PaddingOption::None && plaintext.len() % 16 != 0 {
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

            let output_bytes = match key.len() {
                16 => {
                    let key = AES128Key::from_bytes(key.try_into().unwrap());
                    match padding {
                        PaddingOption::Pkcs7 => {
                            encrypt_bytes(&plaintext, &key, &Pkcs7Padding, mode)
                        }
                        PaddingOption::Zero | PaddingOption::None => {
                            encrypt_bytes(&plaintext, &key, &ZeroPadding, mode)
                        }
                    }
                }
                24 => {
                    let key = AES192Key::from_bytes(key.try_into().unwrap());
                    match padding {
                        PaddingOption::Pkcs7 => {
                            encrypt_bytes(&plaintext, &key, &Pkcs7Padding, mode)
                        }
                        PaddingOption::Zero | PaddingOption::None => {
                            encrypt_bytes(&plaintext, &key, &ZeroPadding, mode)
                        }
                    }
                }
                32 => {
                    let key = AES256Key::from_bytes(key.try_into().unwrap());
                    match padding {
                        PaddingOption::Pkcs7 => {
                            encrypt_bytes(&plaintext, &key, &Pkcs7Padding, mode)
                        }
                        PaddingOption::Zero | PaddingOption::None => {
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
            let key = read_key(key_file).unwrap();

            let mode: EncryptionMode = match (mode.ecb, mode.cbc) {
                (true, false) => EncryptionMode::ECB,
                (false, true) => {
                    let iv = read_iv(iv_file.unwrap()).unwrap();
                    let iv = InitializationVector::from_bytes(iv);

                    EncryptionMode::CBC(iv)
                }
                _ => panic!("Unvalid encryption mode"),
            };

            let mut ciphertext: Vec<u8> = Vec::new();
            if let Some(input_file) = input.input_file {
                let input_file = File::open(&input_file).unwrap_or_else(|err| {
                    eprintln!("Error: {:?}: {}", input_file, err);
                    process::exit(1);
                });

                let mut reader = BufReader::new(input_file);
                reader.read_to_end(&mut ciphertext).unwrap();
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

            let output_bytes = match key.len() {
                16 => {
                    let key = AES128Key::from_bytes(key.try_into().unwrap());
                    match padding {
                        PaddingOption::Pkcs7 => {
                            decrypt_bytes(&ciphertext, &key, Some(Pkcs7Padding), mode).unwrap()
                        }
                        PaddingOption::Zero => {
                            decrypt_bytes(&ciphertext, &key, Some(ZeroPadding), mode).unwrap()
                        }
                        PaddingOption::None => {
                            decrypt_bytes(&ciphertext, &key, None::<ZeroPadding>, mode).unwrap()
                        }
                    }
                }
                24 => {
                    let key = AES192Key::from_bytes(key.try_into().unwrap());
                    match padding {
                        PaddingOption::Pkcs7 => {
                            decrypt_bytes(&ciphertext, &key, Some(Pkcs7Padding), mode).unwrap()
                        }
                        PaddingOption::Zero => {
                            decrypt_bytes(&ciphertext, &key, Some(ZeroPadding), mode).unwrap()
                        }
                        PaddingOption::None => {
                            decrypt_bytes(&ciphertext, &key, None::<ZeroPadding>, mode).unwrap()
                        }
                    }
                }
                32 => {
                    let key = AES256Key::from_bytes(key.try_into().unwrap());
                    match padding {
                        PaddingOption::Pkcs7 => {
                            decrypt_bytes(&ciphertext, &key, Some(Pkcs7Padding), mode).unwrap()
                        }
                        PaddingOption::Zero => {
                            decrypt_bytes(&ciphertext, &key, Some(ZeroPadding), mode).unwrap()
                        }
                        PaddingOption::None => {
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

fn read_key(path: PathBuf) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let meta = f.metadata()?;

    match meta.len() {
        16 | 24 | 32 => (),
        _ => {
            eprintln!(
                "Error: The key must have a size of 128, 192 or 256 bits (16, 24 or 32 bytes)"
            );
            process::exit(1);
        }
    }

    let mut key = Vec::with_capacity(meta.len() as usize);
    f.read_to_end(&mut key)?;

    Ok(key)
}

fn read_iv(path: PathBuf) -> io::Result<[u8; 16]> {
    let mut f = File::open(path)?;
    let meta = f.metadata()?;

    if meta.len() != 16 {
        eprintln!("Error: The IV must have a size of 128 bits (16 bytes)");
        process::exit(1);
    }

    let mut iv: [u8; 16] = Default::default();
    f.read_exact(&mut iv)?;

    Ok(iv)
}

fn write_iv(path: PathBuf, iv: &InitializationVector) -> io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(&iv.as_bytes())?;

    Ok(())
}
