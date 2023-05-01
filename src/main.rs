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
    #[command(alias = "en")]
    Encrypt {
        #[arg(long, short)]
        key_file: PathBuf,

        #[command(flatten)]
        mode: Mode,

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

    #[command(alias = "de")]
    Decrypt {
        #[arg(long, short)]
        key_file: PathBuf,

        #[command(flatten)]
        mode: Mode,

        #[arg(long, short)]
        #[arg(value_enum, default_value_t = Padding::Pkcs7)]
        padding: Padding,

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
    #[arg(long)]
    #[arg(requires = "iv")]
    cbc: bool,

    #[arg(long)]
    #[arg(conflicts_with = "iv")]
    ecb: bool,
}

#[derive(Args, Debug)]
#[group(id = "iv")]
#[group(multiple = false)]
struct Iv {
    #[arg(long)]
    iv_file: Option<PathBuf>,

    #[arg(long)]
    random_iv: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum, Debug)]
enum Padding {
    Pkcs7,
    Zero,
    None,
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
