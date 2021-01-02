use std::collections::HashSet;
use std::io::Read;
use std::iter::FromIterator;
use std::str::FromStr;

use clap::{App, Arg};

#[cfg(test)]
mod test;

#[derive(Debug, PartialEq)]
enum Error {
    InputValueError(&'static str)
}

#[derive(Debug, PartialEq)]
struct Key(Vec<usize>);

impl Key {
    fn new(s: &str) -> Result<Key, Error> {
        let list = s.split_whitespace()
            .map(str::parse)
            .try_fold::<_, _, Result<_, <usize as FromStr>::Err>>(Vec::new(), |mut vec, res| {
                vec.push(res?);
                Ok(vec)
            })
            .map_err(|_| Error::InputValueError("parse error"))?;
        let len = list.len();
        let mut set = HashSet::new();
        if len == 0 || !list.iter().all(|v| {
            let x = *v < len && !set.contains(v);
            set.insert(*v);
            x
        }) {
            return Err(Error::InputValueError("value error"));
        }
        Ok(Key(list))
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn get(&self) -> &[usize] {
        &self.0
    }

    fn small(&self, len: usize) -> Key {
        assert!(len <= self.0.len());
        Key(self.0.iter().filter_map(|v| if *v < len { Some(*v) } else { None }).collect())
    }

    fn inverse(&self) -> Key {
        let mut vec = Vec::with_capacity(self.0.len());
        vec.resize(self.0.len(), 0);
        for &x in &self.0 {
            vec[self.0[x]] = x;
        }
        Key(vec)
    }
}

fn main() {
    let matches = App::new("transposition")
        .about("Transposition cipher")
        .arg(Arg::new("decrypt")
            .short('d')
            .about("flag to decrypt"))
        .arg(Arg::new("key")
            .short('k')
            .about("permutation")
            .takes_value(true)
            .default_value("2 0 3 1"))
        .arg(Arg::new("input")
            .about("input value to encrypt or decrypt"))
        .get_matches();
    let input = matches.value_of("input")
        .map(str::to_string)
        .unwrap_or_else(|| {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).expect("failed to read standard input");
            s
        });
    match Key::new(matches.value_of("key").unwrap()) {
        Ok(key) => {
            if matches.is_present("decrypt") {
                match decrypt(&input, &key) {
                    Ok(result) => println!("{}", result),
                    Err(e) => eprintln!("error:{:?}", e),
                }
            } else {
                match encrypt(&input, &key) {
                    Ok(result) => println!("{}", result),
                    Err(e) => eprintln!("error:{:?}", e),
                }
            }
        }
        Err(e) => {
            eprintln!("error in parsing key:{:?}", e);
        }
    }
}

fn encrypt(input: &str, key: &Key) -> Result<String, Error> {
    let input: Vec<_> = input.chars().collect();
    transpose(&input, key.get(), key.small(input.len() % key.len()).get())
}

fn decrypt(input: &str, key: &Key) -> Result<String, Error> {
    let input: Vec<_> = input.chars().collect();
    transpose(&input, key.inverse().get(), key.small(input.len() % key.len()).inverse().get())
}

fn transpose(input: &Vec<char>, key_block: &[usize], key_mod: &[usize]) -> Result<String, Error> {
    let mut result = Vec::with_capacity(input.len());
    result.resize(input.len(), ' ');

    let block_count = input.len() / key_block.len();
    for block in 0..block_count {
        for i in 0..key_block.len() {
            result[block * key_block.len() + key_block[i]] = input[block * key_block.len() + i];
        }
    }

    for i in 0..key_mod.len() {
        result[block_count * key_block.len() + key_mod[i]] = input[block_count * key_block.len() + i];
    }
    Ok(String::from_iter(result.into_iter()))
}
