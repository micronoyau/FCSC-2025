use capstone::{
    Capstone,
    arch::{self, BuildsCapstone},
};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Check { path: PathBuf },
}

fn isprime(n: u32) -> bool {
    if n < 2 {
        return false;
    }
    for i in 2..((n as f64).sqrt() as u32) {
        if n % i == 0 {
            return false;
        }
    }
    true
}

fn check(path: PathBuf) {
    // Read shellcode as number
    let mut shellcode = std::fs::read(path).unwrap();
    println!(
        "Shellcode = {:02x?} = {}",
        shellcode,
        shellcode
            .iter()
            .map(|x| format!("\\x{:02x}", x))
            .collect::<String>()
    );

    // Pad shellcode
    for _ in 0..((4 - (shellcode.len() % 4)) % 4) {
        shellcode.push(0);
    }

    // Pretty print
    let prime_to_color = |x: bool| {
        if x {
            "PRIME".green()
        } else {
            "NOT PRIME".red()
        }
    };

    println!("\nInstructions: ");
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .build()
        .unwrap();
    let instructions = cs.disasm_all(shellcode.as_slice(), 0x1000).unwrap();
    for instr in instructions.iter() {
        let n = u32::from_le_bytes(instr.bytes().try_into().unwrap());
        println!(
            "{:08x} - {:02x?} - {} - {}",
            n,
            instr.bytes(),
            instr,
            prime_to_color(isprime(n))
        );
    }
}

fn main() {
    // Parse args
    let cli = Cli::parse();
    match cli.command {
        Commands::Check { path } => check(path),
    }
}
