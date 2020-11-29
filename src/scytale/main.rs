use std::io::Read;
use std::iter::FromIterator;

use clap::{App, Arg};
use rand::Rng;

mod test;

#[derive(Debug, PartialEq)]
enum Error {
    InputValueError(&'static str)
}

fn main() {
    let matches = App::new("scytale")
        .about("Scytale cipher")
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

fn encrypt(input: &str, key: usize) -> Result<String, Error> {
    let vec: Vec<_> = input.chars().collect();
    let len = (vec.len() + key - 1) / key * key;
    let mut result_chars = Vec::new();
    let mut rng = rand::thread_rng();
    for i in 0..len / key {
        for j in 0..key {
            let c = vec.get(len / key * j + i).copied().unwrap_or_else(|| vec[rng.gen_range(0, vec.len())]);
            result_chars.push(c);
        }
    }
    Ok(String::from_iter(result_chars.iter()))
}

fn decrypt(input: &str, key: usize) -> Result<String, Error> {
    let vec: Vec<_> = input.chars().collect();
    let len = (vec.len() + key - 1) / key * key;
    let mut result_chars = Vec::new();
    let mut rng = rand::thread_rng();
    for i in 0..key {
        for j in 0..len / key {
            let c = vec.get(j * key + i).copied().unwrap_or_else(|| vec[rng.gen_range(0, vec.len())]);
            result_chars.push(c);
        }
    }
    Ok(String::from_iter(result_chars.iter()))
}