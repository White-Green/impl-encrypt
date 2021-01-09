use std::convert::TryInto;
use std::mem::swap;

use rand::{Rng, thread_rng};
use regex::Regex;

#[cfg(test)]
mod test;

pub fn keygen() -> [bool; 64] {
    let mut rng = thread_rng();
    let mut key: u64 = rng.gen();
    let mut result = [false; 64];
    for i in 0..8 {
        let mut xor = true;
        for j in 0..7 {
            let x = (key & 1) != 0;
            result[i * 8 + j] = x;
            xor ^= x;
            key >>= 1;
        }
        result[i * 8 + 7] = xor;
    }
    result
}

#[derive(Debug, PartialEq)]
pub enum ParseKeyError {
    InvalidKeyStringFormat,
    CheckSumError,
}

pub fn parse_key(key: &str) -> Result<[bool; 64], ParseKeyError> {
    let regex = Regex::new("^[0-9a-fA-F]{16}$").unwrap();
    if !regex.is_match(key) { return Err(ParseKeyError::InvalidKeyStringFormat); }
    let mut result = Vec::with_capacity(64);
    let mut chars = key.chars();
    for _ in 0..16 {
        let c = chars.next().unwrap();
        let value = match c {
            c @ '0'..='9' => { c as u32 - '0' as u32 }
            c @ 'a'..='f' => { c as u32 - 'a' as u32 + 10 }
            c @ 'A'..='F' => { c as u32 - 'A' as u32 + 10 }
            _ => unreachable!()
        };
        for i in 0..4 {
            result.push(((value >> (3 - i)) & 1) == 1);
        }
    }
    let result: [bool; 64] = result.try_into().unwrap();
    if key_checksum(&result) {
        Ok(result)
    } else {
        Err(ParseKeyError::CheckSumError)
    }
}

pub fn key_checksum(key: &[bool; 64]) -> bool {
    for i in 0..8 {
        let mut sum = false;
        for j in 0..8 {
            sum ^= key[i * 8 + j];
        }
        if !sum { return false; }
    }
    true
}

fn pc1<T: Default + Copy>(key: &[T; 64]) -> [T; 56] {
    const TABLE: [usize; 56] = [
        57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4
    ];
    let mut result = [Default::default(); 56];
    for i in 0..56 {
        result[i] = key[TABLE[i] - 1];
    }
    result
}

fn pc2<T: Default + Copy>(key: &[T; 56]) -> [T; 48] {
    const TABLE: [usize; 48] = [
        14, 17, 11, 24, 1, 5,
        3, 28, 15, 6, 21, 10,
        23, 19, 12, 4, 26, 8,
        16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    ];
    let mut result = [Default::default(); 48];
    for i in 0..48 {
        result[i] = key[TABLE[i] - 1];
    }
    result
}

fn rotate_left<T: Default + Clone>(array: &mut [T], count: usize) {
    let count = count % array.len();
    let mut result = vec![Default::default(); array.len()];
    for i in 0..array.len() {
        let value = array[(i + count) % array.len()].clone();
        result[i] = value;
    }
    array.clone_from_slice(&result);
}

fn generate_sub_key<T: Default + Copy>(key: &[T; 64]) -> [[T; 48]; 16] {
    let mut cd = pc1(key);
    let mut result = [[Default::default(); 48]; 16];
    for i in 1..=16 {
        let shift_count = match i {
            1 | 2 | 9 | 16 => 1,
            _ => 2
        };
        rotate_left(&mut cd[..28], shift_count);
        rotate_left(&mut cd[28..], shift_count);
        result[i - 1] = pc2(&cd);
    }
    result
}

fn ip<T: Default + Copy>(input: &[T; 64]) -> [T; 64] {
    const TABLE: [usize; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    ];
    let mut result = [Default::default(); 64];
    for i in 0..64 {
        result[i] = input[TABLE[i] - 1];
    }
    result
}

fn ip_inverse<T: Default + Copy>(input: &[T; 64]) -> [T; 64] {
    const TABLE: [usize; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    ];
    let mut result = [Default::default(); 64];
    for i in 0..64 {
        result[i] = input[TABLE[i] - 1];
    }
    result
}

fn e<T: Default + Copy>(input: &[T; 32]) -> [T; 48] {
    const TABLE: [usize; 48] = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ];
    let mut result = [Default::default(); 48];
    for i in 0..48 {
        result[i] = input[TABLE[i] - 1];
    }
    result
}

fn p<T: Default + Copy>(input: &[T; 32]) -> [T; 32] {
    const TABLE: [usize; 32] = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25
    ];
    let mut result = [Default::default(); 32];
    for i in 0..32 {
        result[i] = input[TABLE[i] - 1];
    }
    result
}

const fn to_bool(input: [[[u8; 16]; 4]; 8]) -> [[[[bool; 4]; 16]; 4]; 8] {
    let mut result = [[[[false; 4]; 16]; 4]; 8];
    let mut i = 0;
    while i < 8 {
        let mut j = 0;
        while j < 4 {
            let mut k = 0;
            while k < 16 {
                result[i][j][k] =
                    [
                        (input[i][j][k] & 0b1000) != 0,
                        (input[i][j][k] & 0b0100) != 0,
                        (input[i][j][k] & 0b0010) != 0,
                        (input[i][j][k] & 0b0001) != 0
                    ];
                k += 1;
            }
            j += 1;
        }
        i += 1;
    }
    result
}

fn s(index: usize, input: &[bool], output: &mut [bool]) {
    const TABLE: [[[[bool; 4]; 16]; 4]; 8] = to_bool([
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]);
    debug_assert_eq!(input.len(), 6);
    debug_assert_eq!(output.len(), 4);

    let index_1 =
        if input[0] { 1 } else { 0 } << 1
            | if input[5] { 1 } else { 0 };
    let index_2 =
        if input[1] { 1 } else { 0 } << 3
            | if input[2] { 1 } else { 0 } << 2
            | if input[3] { 1 } else { 0 } << 1
            | if input[4] { 1 } else { 0 };
    output.clone_from_slice(&TABLE[index][index_1][index_2]);
}

fn f(x: &[bool; 32], k: &[bool; 48]) -> [bool; 32] {
    let mut x1 = [false; 48];
    let e1 = e(x);
    for i in 0..48 {
        x1[i] = e1[i] ^ k[i];
    }
    let mut output = [false; 32];
    for i in 0..8 {
        s(i, &x1[i * 6..(i + 1) * 6], &mut output[i * 4..(i + 1) * 4]);
    }
    p(&output)
}

fn enc(m: &[bool; 64], sub_key: &[[bool; 48]; 16]) -> [bool; 64] {
    let mut m = ip(m);
    let mut l = &mut [false; 32];
    let mut r = &mut [false; 32];
    l.clone_from_slice(&m[..32]);
    r.clone_from_slice(&m[32..]);
    for key in sub_key {
        let y = f(r, key);
        for i in 0..32 {
            l[i] ^= y[i];
        }
        swap::<&mut [bool; 32]>(&mut l, &mut r);
    }
    m[..32].clone_from_slice(r);
    m[32..].clone_from_slice(l);
    ip_inverse(&m)
}

fn pick_64bit_from_slice(input: &[u8]) -> [bool; 64] {
    let mut result = [false; 64];
    for (value, i) in input.iter().zip(0..8) {
        result[i * 8 + 0] = (value & 0b10000000) != 0;
        result[i * 8 + 1] = (value & 0b01000000) != 0;
        result[i * 8 + 2] = (value & 0b00100000) != 0;
        result[i * 8 + 3] = (value & 0b00010000) != 0;
        result[i * 8 + 4] = (value & 0b00001000) != 0;
        result[i * 8 + 5] = (value & 0b00000100) != 0;
        result[i * 8 + 6] = (value & 0b00000010) != 0;
        result[i * 8 + 7] = (value & 0b00000001) != 0;
    }
    result
}

pub(crate) fn push_64bit(vec: &mut Vec<u8>, value: [bool; 64]) {
    for i in 0..8 {
        let mut v = 0;
        for j in 0..8 {
            v <<= 1;
            v |= if value[i * 8 + j] { 1 } else { 0 };
        }
        vec.push(v);
    }
}

pub fn encrypt(input: &[u8], key: &[bool; 64]) -> Vec<u8> {
    let sub_key = generate_sub_key(key);
    let mut result = Vec::with_capacity((input.len() + 7) & !7);
    for i in 0..(input.len() + 7) / 8 {
        let block = pick_64bit_from_slice(&input[i * 8..]);
        let block = enc(&block, &sub_key);
        push_64bit(&mut result, block);
    }
    result
}

pub fn decrypt(input: &[u8], key: &[bool; 64]) -> Vec<u8> {
    let mut sub_key = generate_sub_key(key);
    let (l, r) = sub_key.split_at_mut(8);
    for i in 0..8 {
        swap(&mut l[i], &mut r[7 - i]);
    }
    let mut result = Vec::with_capacity((input.len() + 7) & !7);
    for i in 0..(input.len() + 7) / 8 {
        let block = pick_64bit_from_slice(&input[i * 8..]);
        let block = enc(&block, &sub_key);
        push_64bit(&mut result, block);
    }
    result
}
