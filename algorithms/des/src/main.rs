use clap::{App, Arg, SubCommand};

use lib::{decrypt, encrypt, keygen, parse_key, push_64bit};
use std::io::Read;

mod lib;

fn main() {
    let matches = App::new("des")
        .about("DES cipher")
        .subcommand(SubCommand::with_name("keygen")
            .about("generate new key by random"))
        .arg(Arg::with_name("decrypt")
            .short("d")
            .long("decrypt")
            .help("flag to decrypt"))
        .arg(Arg::with_name("key")
            .short("k")
            .long("key")
            .help("Key for encrypt or decrypt")
            .takes_value(true))
        .arg(Arg::with_name("hex")
            .short("x")
            .long("hex")
            .help("flag to encrypt input as hex value(when decrypt this flag is ignored)"))
        .arg(Arg::with_name("input")
            .help("input value to encrypt or decrypt"))
        .get_matches();
    if let Some(_) = matches.subcommand_matches("keygen") {
        let key = keygen();
        let mut vec = Vec::with_capacity(8);
        push_64bit(&mut vec, key);
        let key = binary_to_hex_string(vec);
        println!("generated key: {}", key);
    } else {
        let input = matches.value_of("input").map(str::to_string).unwrap_or_else(|| {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).expect("failed to read standard input");
            s
        });
        let input = if !matches.is_present("decrypt") && !matches.is_present("hex") {
            utf8_to_binary(&input)
        } else {
            hex_string_to_binary(&input)
        };
        let input = match input {
            Ok(input) => input,
            Err(e) => {
                eprintln!("error in parsing input: {:?}", e);
                return;
            }
        };
        match parse_key(matches.value_of("key").unwrap()) {
            Ok(key) => {
                if matches.is_present("decrypt") {
                    let result = encrypt(&input, &key);
                    if !matches.is_present("hex") {
                        let string = String::from_utf8(result).expect("failed to encode to utf8 decrypt result.");
                        println!("{}", string);
                    } else {
                        println!("{}", binary_to_hex_string(result));
                    }
                } else {
                    let result = decrypt(&input, &key);
                    println!("{}", binary_to_hex_string(result));
                }
            }
            Err(e) => {
                eprintln!("error in parsing key: {:?}", e);
            }
        }
    }
}


#[derive(Debug, PartialEq)]
enum InputToBinaryError {
    InvalidHexString
}

fn utf8_to_binary(value: &str) -> Result<Vec<u8>, InputToBinaryError> {
    Ok(value.as_bytes().into())
}

fn hex_string_to_binary(value: &str) -> Result<Vec<u8>, InputToBinaryError> {
    let mut result = Vec::with_capacity(value.len() >> 1);
    let mut chars = value.chars();
    let char_to_int = |c| match c {
        c @ '0'..='9' => Some(c as u8 - '0' as u8),
        c @ 'a'..='f' => Some(c as u8 - 'a' as u8 + 10),
        c @ 'A'..='F' => Some(c as u8 - 'A' as u8 + 10),
        _ => None
    };
    while let Some(c) = chars.next() {
        let upper = match char_to_int(c) {
            Some(value) => value,
            None => return Err(InputToBinaryError::InvalidHexString)
        };
        let lower = match chars.next() {
            Some(c) =>
                match char_to_int(c) {
                    Some(value) => value,
                    None => return Err(InputToBinaryError::InvalidHexString)
                },
            None => return Err(InputToBinaryError::InvalidHexString)
        };
        result.push(upper << 4 | lower);
    }
    Ok(result)
}

fn binary_to_hex_string(value: Vec<u8>) -> String {
    let mut result = String::with_capacity(value.len() * 2);
    for value in value {
        result.push_str(&format!("{:02x}", value));
    }
    result
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_utf8_to_binary() {
        assert_eq!(utf8_to_binary("abc"), Ok(vec!['a' as u8, 'b' as u8, 'c' as u8]));
    }

    #[test]
    fn test_hex_string_to_binary() {
        assert_eq!(hex_string_to_binary("0123456789abcdef"), Ok(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]));
        assert!(hex_string_to_binary("0123456789abcde").is_err());
        assert!(hex_string_to_binary("0123456789abcdefg").is_err());
    }

    #[test]
    fn test_binary_to_hex_string() {
        assert_eq!(binary_to_hex_string(vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]), String::from("0123456789abcdef"));
        assert_eq!(binary_to_hex_string((0..=255).into_iter().collect()), String::from("000102030405060708090a0b0c0d0e0f\
101112131415161718191a1b1c1d1e1f\
202122232425262728292a2b2c2d2e2f\
303132333435363738393a3b3c3d3e3f\
404142434445464748494a4b4c4d4e4f\
505152535455565758595a5b5c5d5e5f\
606162636465666768696a6b6c6d6e6f\
707172737475767778797a7b7c7d7e7f\
808182838485868788898a8b8c8d8e8f\
909192939495969798999a9b9c9d9e9f\
a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\
b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
c0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
    }
}
