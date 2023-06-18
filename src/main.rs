use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process;

use clap::{Args, Parser, Subcommand, ValueEnum};

use aesculap::key::{AES128Key, AES192Key, AES256Key, Key};
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
    env_logger::init();

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
                        panic!("Invalid IV state");
                    }
                }
                _ => panic!("Invalid encryption mode"),
            };

            let input = match (input.input_file, input.stdin) {
                (Some(path), false) => read_file(path).unwrap(),
                (None, true) => read_stdin().unwrap(),
                _ => panic!("Invalid input"),
            };

            if padding == PaddingOption::None && input.len() % 16 != 0 {
                eprintln!(
                    "Error: Without padding the number of input bytes has to be divisible by 16"
                );
                process::exit(1);
            }

            let mut output: Box<dyn Write> = match (output.output_file, output.stdout) {
                (Some(path), false) => {
                    let f = File::create(path).unwrap();
                    Box::new(f)
                }
                (None, true) => Box::new(io::stdout().lock()),
                _ => panic!("Invalid output"),
            };

            let output_bytes = match key.len() {
                16 => {
                    let key = AES128Key::from_bytes(key.try_into().unwrap());
                    encrypt(&input, &key, padding, mode)
                }
                24 => {
                    let key = AES192Key::from_bytes(key.try_into().unwrap());
                    encrypt(&input, &key, padding, mode)
                }
                32 => {
                    let key = AES256Key::from_bytes(key.try_into().unwrap());
                    encrypt(&input, &key, padding, mode)
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
                _ => panic!("Invalid encryption mode"),
            };

            let input = match (input.input_file, input.stdin) {
                (Some(path), false) => read_file(path).unwrap(),
                (None, true) => read_stdin().unwrap(),
                _ => panic!("Invalid input"),
            };

            let mut output: Box<dyn Write> = match (output.output_file, output.stdout) {
                (Some(path), false) => {
                    let f = File::create(path).unwrap();
                    Box::new(f)
                }
                (None, true) => Box::new(io::stdout().lock()),
                _ => panic!("Invalid output"),
            };

            let output_bytes = match key.len() {
                16 => {
                    let key = AES128Key::from_bytes(key.try_into().unwrap());
                    decrypt(&input, &key, padding, mode)
                }
                24 => {
                    let key = AES192Key::from_bytes(key.try_into().unwrap());
                    decrypt(&input, &key, padding, mode)
                }
                32 => {
                    let key = AES256Key::from_bytes(key.try_into().unwrap());
                    decrypt(&input, &key, padding, mode)
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

fn read_file(path: PathBuf) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let meta = f.metadata()?;

    let mut file = Vec::with_capacity(meta.len() as usize);
    f.read_to_end(&mut file)?;

    Ok(file)
}

fn read_stdin() -> io::Result<Vec<u8>> {
    let stdin = io::stdin();
    let mut buffer = Vec::new();

    {
        let mut stdin = stdin.lock();
        stdin.read_to_end(&mut buffer)?;
    }

    Ok(buffer)
}

fn write_iv(path: PathBuf, iv: &InitializationVector) -> io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(&iv.as_bytes())?;

    Ok(())
}

fn encrypt<const N: usize, K>(
    plaintext: &[u8],
    key: &K,
    padding: PaddingOption,
    mode: EncryptionMode,
) -> Vec<u8>
where
    K: Key<N>,
{
    match padding {
        PaddingOption::Pkcs7 => encrypt_bytes(plaintext, key, &Pkcs7Padding, mode),
        PaddingOption::Zero | PaddingOption::None => {
            encrypt_bytes(plaintext, key, &ZeroPadding, mode)
        }
    }
}

fn decrypt<const N: usize, K>(
    ciphertext: &[u8],
    key: &K,
    padding: PaddingOption,
    mode: EncryptionMode,
) -> Vec<u8>
where
    K: Key<N>,
{
    match padding {
        PaddingOption::Pkcs7 => decrypt_bytes(ciphertext, key, Some(Pkcs7Padding), mode).unwrap(),
        PaddingOption::Zero => decrypt_bytes(ciphertext, key, Some(ZeroPadding), mode).unwrap(),
        PaddingOption::None => decrypt_bytes(ciphertext, key, None::<ZeroPadding>, mode).unwrap(),
    }
}
