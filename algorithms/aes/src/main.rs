use std::io::Read;

use clap::{App, Arg, SubCommand};

use crate::lib::{decrypt, encrypt, keygen_128, keygen_192, keygen_256, parse_key};

mod lib;

fn main() {
    let matches = App::new("aes")
        .about("AES cipher")
        .subcommand(SubCommand::with_name("keygen")
            .about("generate new key by random")
            .arg(Arg::with_name("length")
                .short("l")
                .long("length")
                .help("length of key(either 128 192 or 256)")
                .takes_value(true)))
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
    if let Some(matches) = matches.subcommand_matches("keygen") {
        let key = match matches.value_of("length") {
            Some("128") | None => keygen_128(),
            Some("192") => keygen_192(),
            Some("256") => keygen_256(),
            _ => {
                eprintln!("Value of length must be either 128 192 or 256.");
                return;
            }
        };
        let key = binary_to_hex_string(key.as_slice());
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
                        println!("{}", binary_to_hex_string(&result));
                    }
                } else {
                    let result = decrypt(&input, &key);
                    println!("{}", binary_to_hex_string(&result));
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

fn binary_to_hex_string(value: &[u8]) -> String {
    let mut result = String::with_capacity(value.len() * 2);
    for value in value {
        result.push_str(&format!("{:02x}", value));
    }
    result
}

#[cfg(test)]
mod test{
    use super::*;

    #[test]
    fn test_hex_string_to_binary() {
        assert_eq!(hex_string_to_binary("000102030405060708090a0b0c0d0e0f"),
                   Ok(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]));
        assert!(hex_string_to_binary("a").is_err());
        assert!(hex_string_to_binary("0g").is_err());
    }

    #[test]
    fn test_binary_to_hex_string() {
        assert_eq!(binary_to_hex_string(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
                   "000102030405060708090a0b0c0d0e0f".to_string());
    }

}
