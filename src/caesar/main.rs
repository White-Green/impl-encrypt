use std::io::Read;

use clap::{App, Arg};

mod test;

#[derive(Debug, PartialEq)]
enum Error {
    InputValueError(&'static str)
}

fn main() {
    let matches = App::new("caesar")
        .about("Caesar cipher")
        .arg(Arg::new("decrypt")
            .short('d')
            .about("flag to decrypt"))
        .arg(Arg::new("key")
            .short('k')
            .about("amount of rotate")
            .takes_value(true)
            .default_value("3"))
        .arg(Arg::new("input")
            .about("input value to encrypt or decrypt"))
        .get_matches();
    let input = matches.value_of("input").map(str::to_string).unwrap_or_else(|| {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).expect("failed to read standard input");
        s
    });
    if let Ok(key) = matches.value_of("key").unwrap().parse() {
        if matches.is_present("decrypt") {
            match decrypt(&input, key) {
                Ok(result) => println!("{}", result),
                Err(e) => eprintln!("error:{:?}", e),
            }
        } else {
            match encrypt(&input, key) {
                Ok(result) => println!("{}", result),
                Err(e) => eprintln!("error:{:?}", e),
            }
        }
    } else {
        eprintln!("argument 'key' should be number");
    }
}

const ALPHABET_COUNT: u8 = 26;

fn encrypt(input: &str, key: usize) -> Result<String, Error> {
    if input.chars().any(|c| !c.is_alphabetic() || !c.is_lowercase()) {
        return Err(Error::InputValueError("All input characters should be lowercase alphabet."));
    }
    let mut result = String::with_capacity(input.chars().count());
    let key = (key % ALPHABET_COUNT as usize) as u8;
    for c in input.chars() {
        result.push(((c as u8 - 'a' as u8 + key) % ALPHABET_COUNT + 'a' as u8) as char);
    }
    Ok(result)
}

fn decrypt(input: &str, key: usize) -> Result<String, Error> {
    if input.chars().any(|c| !c.is_alphabetic() || !c.is_lowercase()) {
        return Err(Error::InputValueError("All input characters should be lowercase alphabet."));
    }
    let mut result = String::with_capacity(input.chars().count());
    let key = (key % ALPHABET_COUNT as usize) as u8;
    for c in input.chars() {
        result.push(((c as u8 - 'a' as u8 + ALPHABET_COUNT - key) % ALPHABET_COUNT + 'a' as u8) as char);
    }
    Ok(result)
}