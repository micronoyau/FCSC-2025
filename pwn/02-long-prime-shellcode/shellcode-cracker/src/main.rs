use mbedtls::{
    bignum::Mpi,
    rng::{CtrDrbg, Random, Rdseed},
};
use rand::Rng;
use std::env;

const BYTE_PRIMES: [u8; 54] = [
    0x02, 0x03, 0x05, 0x07, 0x0b, 0x0d, 0x11, 0x13, 0x17, 0x1d, 0x1f, 0x25, 0x29, 0x2b, 0x2f, 0x35,
    0x3b, 0x3d, 0x43, 0x47, 0x49, 0x4f, 0x53, 0x59, 0x61, 0x65, 0x67, 0x6b, 0x6d, 0x71, 0x7f, 0x83,
    0x89, 0x8b, 0x95, 0x97, 0x9d, 0xa3, 0xa7, 0xad, 0xb3, 0xb5, 0xbf, 0xc1, 0xc5, 0xc7, 0xd3, 0xdf,
    0xe3, 0xe5, 0xe9, 0xef, 0xf1, 0xfb,
];

const MIN_BITLEN: usize = 0x400;
const MAX_BITLEN: usize = 0x1000;

fn main() {
    // Parse args
    let shellcode_path = env::args()
        .skip(1)
        .next()
        .expect("Usage: shellcode-cracker <path/to/shellcode.bin>");
    println!("Selected shellcode {}", shellcode_path);

    // Read shellcode as number
    let mut shellcode = std::fs::read(shellcode_path).unwrap();
    let number = Mpi::from_binary(&shellcode).unwrap();
    println!(
        "Desired MSB for prime number: {:02x?} = {}",
        shellcode, number
    );

    // Seed RNG
    let mut mbed_rng = CtrDrbg::new(Rdseed.into(), Some(b"fcsc2025")).unwrap();
    let mut rand_rng = rand::rng();

    // Fill number to have enough bits
    let number_bitlen = number.bit_length().unwrap();
    let mut number_extension = vec![0u8; (MIN_BITLEN - number_bitlen) >> 3];
    mbed_rng.random(&mut number_extension).unwrap();
    shellcode.extend(number_extension);
    let mut number = Mpi::from_binary(&shellcode).unwrap();
    println!(
        "Extended shellcode to match minimum size: {:02x?} = {}",
        shellcode, number
    );

    println!("\n*** Starting bruteforce ***\n");
    while number.bit_length().unwrap() < MAX_BITLEN {
        // Try last byte to every prime number
        shellcode.push(0);
        for p in BYTE_PRIMES {
            *shellcode.last_mut().unwrap() = p;
            number = Mpi::from_binary(&shellcode).unwrap();
            if number.is_probably_prime(0x2a, &mut mbed_rng).is_ok() {
                println!("Found number!");
                println!("Number = {:02x?} = {}", number.to_binary().unwrap(), number);
                return;
            }
        }

        // If it failed, set this byte to random number and keep going to next byte
        *shellcode.last_mut().unwrap() = rand_rng.random::<u8>();
        number = Mpi::from_binary(&shellcode).unwrap();

        println!("Failed... trying {:02x?}", number.to_binary().unwrap())
    }
}
