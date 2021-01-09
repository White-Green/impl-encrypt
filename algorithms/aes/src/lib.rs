use std::convert::TryInto;
use std::ops::Mul;
use regex::Regex;
use rand::{thread_rng, Rng};

#[cfg(test)]
mod test;
#[derive(Debug, Clone, PartialEq)]
pub enum Key {
    AES128([u8; 16]),
    AES192([u8; 24]),
    AES256([u8; 32]),
}

impl Key {
    pub(crate)fn as_slice(&self) -> &[u8] {
        match self {
            Key::AES128(key) => key,
            Key::AES192(key) => key,
            Key::AES256(key) => key,
        }
    }

    fn to_u32(&self) -> Vec<u32> {
        let slice = self.as_slice();
        let mut vec = Vec::with_capacity(slice.len() / 4);
        vec.resize(slice.len() / 4, 0);
        let mut slice_index = 0;
        for i in 0..vec.len() {
            for _ in 0..4 {
                vec[i] <<= 1;
                vec[i] |= slice[slice_index] as u32;
                slice_index += 1;
            }
        }
        vec
    }
}

pub fn keygen_128() -> Key {
    let mut rng = thread_rng();
    let mut key: u128 = rng.gen();
    let mut result = [0; 128 / 8];
    for i in 0..16 {
        result[i] = (key & 0xff) as u8;
        key >>= 1;
    }
    Key::AES128(result)
}

pub fn keygen_192() -> Key {
    let mut rng = thread_rng();
    let mut key: u128 = rng.gen();
    let mut result = [0; 196 / 8];
    for i in 0..16 {
        result[i] = (key & 0xff) as u8;
        key >>= 1;
    }
    let mut key: u64 = rng.gen();
    for i in 16..24 {
        result[i] = (key & 0xff) as u8;
        key >>= 1;
    }
    Key::AES192(result)
}

pub fn keygen_256() -> Key {
    let mut rng = thread_rng();
    let mut key: u128 = rng.gen();
    let mut result = [0; 256 / 8];
    for i in 0..16 {
        result[i] = (key & 0xff) as u8;
        key >>= 1;
    }
    let mut key: u128 = rng.gen();
    for i in 16..32 {
        result[i] = (key & 0xff) as u8;
        key >>= 1;
    }
    Key::AES256(result)
}

#[derive(Debug, PartialEq)]
pub enum ParseKeyError {
    InvalidKeyStringFormat,
}

pub fn parse_key(key: &str) -> Result<Key, ParseKeyError> {
    let regex = Regex::new("^[0-9a-fA-F]+$").unwrap();
    if !regex.is_match(key) { return Err(ParseKeyError::InvalidKeyStringFormat); }
    let mut result = Vec::with_capacity(32);
    let mut chars = key.chars();
    fn char_to_u8(input: char) -> u8 {
        match input {
            c @ '0'..='9' => { c as u8 - '0' as u8 }
            c @ 'a'..='f' => { c as u8 - 'a' as u8 + 10 }
            c @ 'A'..='F' => { c as u8 - 'A' as u8 + 10 }
            _ => unreachable!()
        }
    }
    for _ in 0..33 {
        let mut byte = if let Some(c) = chars.next() { char_to_u8(c) << 4 } else { break; };
        byte |= if let Some(c) = chars.next() { char_to_u8(c) } else { return Err(ParseKeyError::InvalidKeyStringFormat); };
        result.push(byte);
    }
    match result.len() {
        16 => { Ok(Key::AES128(result.try_into().unwrap())) }
        24 => { Ok(Key::AES192(result.try_into().unwrap())) }
        32 => { Ok(Key::AES256(result.try_into().unwrap())) }
        _ => Err(ParseKeyError::InvalidKeyStringFormat)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Polynomial(u8);

impl Mul for Polynomial {
    type Output = Polynomial;

    fn mul(self, rhs: Self) -> Self::Output {
        let a = self.0;
        let b = rhs.0;
        let b = (b & 0x55) << 1 | (b & 0xaa) >> 1;
        let b = (b & 0x33) << 2 | (b & 0xcc) >> 2;
        let b = (b & 0x0f) << 4 | (b & 0xf0) >> 4;
        fn pop_count(c: u8) -> u8 {
            let c = (c & 0x55) ^ ((c >> 1) & 0x55);
            let c = (c & 0x33) ^ ((c >> 2) & 0x33);
            (c & 0x0f) ^ ((c >> 4) & 0x0f)
        }
        let mut i = 0;
        let mut result: u32 = 0;
        for j in 0..8 {
            let c = pop_count(a & b >> (7 - j));
            result |= (c as u32) << i;
            i += 1;
        }
        for j in 1..8 {
            let c = pop_count(a & b << j);
            result |= (c as u32) << i;
            i += 1;
        }
        let mut modulo = 0b100011011_0000000;
        let mut mask = 0b100000000_0000000;
        while result > 255 {
            if (result & mask) != 0 {
                result ^= modulo;
            }
            modulo >>= 1;
            mask >>= 1;
        }
        Polynomial(result as u8)
    }
}

fn rot_word(input: u32) -> u32 {
    input << 8 | input >> 24
}

fn sub_byte(input: u8) -> u8 {
    const TABLE: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];
    TABLE[input as usize]
}

fn sub_word(input: u32) -> u32 {
    (sub_byte(((input >> 24) & 0xff) as u8) as u32) << 24 |
        (sub_byte(((input >> 16) & 0xff) as u8) as u32) << 16 |
        (sub_byte(((input >> 8) as u8) & 0xff) as u32) << 8 |
        (sub_byte((input & 0xff) as u8) as u32)
}

// fn inner(key: &mut [u32], key_count: usize) -> Vec<[u32; 4]> {
//     debug_assert!(key.len() == 4 || key.len() == 6 || key.len() == 8);
//     debug_assert!(key_count == 11 || key_count == 13 || key_count == 15);
//     let mut key_words = Vec::with_capacity((key_count * 4 + key.len() - 1) / key.len());
//     let mut rcon = Polynomial(1);
//     loop {
//         for j in key.iter() {
//             key_words.push(*j);
//         }
//         if key_words.len() >= key_count * 4 { break; }
//         let mut tmp = sub_word(rot_word(key[3])) ^ ((rcon.0 as u32) << 24);
//         rcon = rcon * Polynomial(0b10);
//         if key.len() == 8 {
//             for i in 0..4 {
//                 key[i] ^= tmp;
//                 tmp = key[i];
//             }
//             tmp = sub_word(tmp);
//             for i in 4..8 {
//                 key[i] ^= tmp;
//                 tmp = key[i];
//             }
//         } else {
//             for i in 0..key.len() {
//                 key[i] ^= tmp;
//                 tmp = key[i];
//             }
//         }
//     }
//     let mut sub_key = Vec::with_capacity(key_count);
//     for i in 0..key_count {
//         sub_key[i] = [
//             key_words[i * 4],
//             key_words[i * 4 + 1],
//             key_words[i * 4 + 2],
//             key_words[i * 4 + 3],
//         ];
//     }
//     sub_key
// }
//
// fn generate_sub_key_192(mut key: [u32; 6]) -> [[u32; 4]; 12] {
//     let mut key_words = Vec::with_capacity(40);
//     let mut rcon = Polynomial(1);
//     loop {
//         for j in 0..4 {
//             key_words.push(key[j]);
//         }
//         if key_words.len() >= 40 { break; }
//         let mut tmp = sub_word(rot_word(key[3])) ^ ((rcon.0 as u32) << 24);
//         rcon = rcon * Polynomial(0b10);
//         for i in 0..4 {
//             key[i] ^= tmp;
//             tmp = key[i];
//         }
//     }
//     let mut sub_key = Vec::with_capacity(10);
//     for i in 0..10 {
//         sub_key[i] = [
//             key_words[i * 4],
//             key_words[i * 4 + 1],
//             key_words[i * 4 + 2],
//             key_words[i * 4 + 3],
//         ];
//     }
//     sub_key.try_into().unwrap()
// }
//
// fn generate_sub_key_256(key: [u32; 8]) -> [[u32; 4]; 14] {
//     unimplemented!()
// }

#[derive(Debug, Clone, PartialEq)]
enum SubKey {
    AES128([[u32; 4]; 11]),
    AES192([[u32; 4]; 13]),
    AES256([[u32; 4]; 15]),
}

impl SubKey {
    fn transpose(&self) -> Vec<[u32; 4]> {
        let (slice, len): (&[[u32; 4]], _) = match self {
            SubKey::AES128(slice) => (slice, 11),
            SubKey::AES192(slice) => (slice, 13),
            SubKey::AES256(slice) => (slice, 15),
        };
        let mut vec = Vec::with_capacity(len);
        for x in slice {
            let mut matrix = [0; 4];
            for r in 0..4 {
                for c in 0..4 {
                    matrix[r] |= ((x[c] >> ((3 - r) * 8)) & 0xff) << ((3 - c) * 8);
                }
            }
            vec.push(matrix);
        }
        vec
    }
}

fn generate_sub_key(key: &Key) -> SubKey {
    fn inner(key: &mut [u32], key_count: usize) -> Vec<[u32; 4]> {
        debug_assert!(key.len() == 4 || key.len() == 6 || key.len() == 8);
        debug_assert!(key_count == 11 || key_count == 13 || key_count == 15);
        let mut key_words = Vec::with_capacity((key_count * 4 + key.len() - 1) / key.len());
        let mut rcon = Polynomial(1);
        loop {
            for j in key.iter() {
                key_words.push(*j);
            }
            if key_words.len() >= key_count * 4 { break; }
            let mut tmp = sub_word(rot_word(key[3])) ^ ((rcon.0 as u32) << 24);
            rcon = rcon * Polynomial(0b10);
            if key.len() == 8 {
                for i in 0..4 {
                    key[i] ^= tmp;
                    tmp = key[i];
                }
                tmp = sub_word(tmp);
                for i in 4..8 {
                    key[i] ^= tmp;
                    tmp = key[i];
                }
            } else {
                for i in 0..key.len() {
                    key[i] ^= tmp;
                    tmp = key[i];
                }
            }
        }
        let mut sub_key = Vec::with_capacity(key_count);
        for i in 0..key_count {
            sub_key.push([
                key_words[i * 4],
                key_words[i * 4 + 1],
                key_words[i * 4 + 2],
                key_words[i * 4 + 3],
            ]);
        }
        sub_key
    }
    match key {
        Key::AES128(_) => SubKey::AES128(inner(&mut key.to_u32(), 11).try_into().unwrap()),
        Key::AES192(_) => SubKey::AES192(inner(&mut key.to_u32(), 13).try_into().unwrap()),
        Key::AES256(_) => SubKey::AES256(inner(&mut key.to_u32(), 15).try_into().unwrap()),
    }
}

fn sub_bytes(state: &mut [u32; 4]) {
    for i in 0..4 {
        state[i] = sub_word(state[i]);
    }
}

fn shift_rows(state: &mut [u32; 4]) {
    state[1] = state[1] << 08 | state[1] >> 24;
    state[2] = state[2] << 16 | state[2] >> 16;
    state[3] = state[3] << 24 | state[3] >> 08;
}

fn mix_columns(state: &mut [u32; 4]) {
    const MATRIX: [[Polynomial; 4]; 4] = [
        [Polynomial(0b10), Polynomial(0b11), Polynomial(0b01), Polynomial(0b01)],
        [Polynomial(0b01), Polynomial(0b10), Polynomial(0b11), Polynomial(0b01)],
        [Polynomial(0b01), Polynomial(0b01), Polynomial(0b10), Polynomial(0b11)],
        [Polynomial(0b11), Polynomial(0b01), Polynomial(0b01), Polynomial(0b10)],
    ];
    let mut result = [0; 4];
    for r in 0..4 {
        for d in 0..4 {
            result[r] ^=
                ((Polynomial(((state[d] >> 24) & 0xff) as u8) * MATRIX[r][d]).0 as u32) << 24 |
                    ((Polynomial(((state[d] >> 16) & 0xff) as u8) * MATRIX[r][d]).0 as u32) << 16 |
                    ((Polynomial(((state[d] >> 08) & 0xff) as u8) * MATRIX[r][d]).0 as u32) << 08 |
                    ((Polynomial(((state[d] >> 00) & 0xff) as u8) * MATRIX[r][d]).0 as u32) << 00;
        }
    }
    *state = result;
}

fn add_round_key(state: &mut [u32; 4], key: &[u32; 4]) {
    for i in 0..4 {
        state[i] ^= key[i];
    }
}

fn inv_sub_byte(input: u8) -> u8 {
    const TABLE: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ];
    TABLE[input as usize]
}

fn inv_sub_word(input: u32) -> u32 {
    (inv_sub_byte(((input >> 24) & 0xff) as u8) as u32) << 24 |
        (inv_sub_byte(((input >> 16) & 0xff) as u8) as u32) << 16 |
        (inv_sub_byte(((input >> 8) as u8) & 0xff) as u32) << 8 |
        (inv_sub_byte((input & 0xff) as u8) as u32)
}

fn inv_sub_bytes(state: &mut [u32; 4]) {
    for i in 0..4 {
        state[i] = inv_sub_word(state[i]);
    }
}

fn inv_shift_rows(state: &mut [u32; 4]) {
    state[1] = state[1] >> 08 | state[1] << 24;
    state[2] = state[2] >> 16 | state[2] << 16;
    state[3] = state[3] >> 24 | state[3] << 08;
}

fn inv_mix_columns(state: &mut [u32; 4]) {
    const MATRIX: [[Polynomial; 4]; 4] = [
        [Polynomial(0b1110), Polynomial(0b1011), Polynomial(0b1101), Polynomial(0b1001)],
        [Polynomial(0b1001), Polynomial(0b1110), Polynomial(0b1011), Polynomial(0b1101)],
        [Polynomial(0b1101), Polynomial(0b1001), Polynomial(0b1110), Polynomial(0b1011)],
        [Polynomial(0b1011), Polynomial(0b1101), Polynomial(0b1001), Polynomial(0b1110)],
    ];
    let mut result = [0; 4];
    for r in 0..4 {
        for d in 0..4 {
            result[r] ^=
                ((Polynomial(((state[d] >> 24) & 0xff) as u8) * MATRIX[r][d]).0 as u32) << 24 |
                    ((Polynomial(((state[d] >> 16) & 0xff) as u8) * MATRIX[r][d]).0 as u32) << 16 |
                    ((Polynomial(((state[d] >> 08) & 0xff) as u8) * MATRIX[r][d]).0 as u32) << 08 |
                    ((Polynomial(((state[d] >> 00) & 0xff) as u8) * MATRIX[r][d]).0 as u32) << 00;
        }
    }
    *state = result;
}

fn inv_add_round_key(state: &mut [u32; 4], key: &[u32; 4]) {
    add_round_key(state, key);
}

fn encrypt_inner(mut state: [u32; 4], sub_key: &[[u32; 4]]) -> [u32; 4] {
    let mut key_iter = sub_key.iter().peekable();
    add_round_key(&mut state, key_iter.next().unwrap());
    while let Some(key) = key_iter.next() {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        if let Some(_) = key_iter.peek() {
            mix_columns(&mut state);
        }
        add_round_key(&mut state, key);
    }
    state
}

fn decrypt_inner(mut state: [u32; 4], sub_key: &[[u32; 4]]) -> [u32; 4] {
    let mut key_iter = sub_key.iter().rev();
    let last_key = key_iter.next_back().unwrap();
    let key = key_iter.next().unwrap();
    inv_add_round_key(&mut state, key);
    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    while let Some(key) = key_iter.next() {
        inv_add_round_key(&mut state, key);
        inv_mix_columns(&mut state);
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
    }
    inv_add_round_key(&mut state, last_key);
    state
}

fn pick_state_from_slice(slice: &[u8]) -> [u32; 4] {
    let mut state = [0; 4];
    for i in 0..4 {
        for j in 0..4 {
            state[j] <<= 8;
            state[j] |= slice.get(i * 4 + j).map(|v| *v as u32).unwrap_or(0);
        }
    }
    state
}

fn push_state(vec: &mut Vec<u8>, state: [u32; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            vec.push(((state[j] >> (3 - i) * 8) & 0xff) as u8);
        }
    }
}

pub fn encrypt(input: &[u8], key: &Key) -> Vec<u8> {
    let sub_key = generate_sub_key(key).transpose();
    let mut result = Vec::with_capacity((input.len() + 15) & !15);
    for i in 0..(input.len() + 15) / 16 {
        push_state(&mut result, encrypt_inner(pick_state_from_slice(&input[i * 16..]), &sub_key));
    }
    result
}

pub fn decrypt(input: &[u8], key: &Key) -> Vec<u8> {
    let sub_key = generate_sub_key(key).transpose();
    let mut result = Vec::with_capacity((input.len() + 15) & !15);
    for i in 0..(input.len() + 15) / 16 {
        push_state(&mut result, decrypt_inner(pick_state_from_slice(&input[i * 16..]), &sub_key));
    }
    result
}
