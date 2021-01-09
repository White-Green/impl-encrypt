use std::convert::TryInto;

use rand::{Rng, thread_rng};

use crate::{binary_to_hex_string, decrypt, e, encrypt, generate_sub_key, hex_string_to_binary, ip, ip_inverse, key_checksum, keygen, p, parse_key, pc1, pc2, pick_64bit_from_slice, push_64bit, rotate_left, s, utf8_to_binary};

#[test]
fn test_parse_key() {
    assert_eq!(parse_key("0101010101010101"), Ok([false, false, false, false,
        false, false, false, true,
        false, false, false, false,
        false, false, false, true,
        false, false, false, false,
        false, false, false, true,
        false, false, false, false,
        false, false, false, true,
        false, false, false, false,
        false, false, false, true,
        false, false, false, false,
        false, false, false, true,
        false, false, false, false,
        false, false, false, true,
        false, false, false, false,
        false, false, false, true]));

    assert_eq!(parse_key("0123456789abcdef"), Ok([false, false, false, false,
        false, false, false, true,
        false, false, true, false,
        false, false, true, true,
        false, true, false, false,
        false, true, false, true,
        false, true, true, false,
        false, true, true, true,
        true, false, false, false,
        true, false, false, true,
        true, false, true, false,
        true, false, true, true,
        true, true, false, false,
        true, true, false, true,
        true, true, true, false,
        true, true, true, true]));

    assert!(parse_key("010101010101010").is_err());
    assert!(parse_key("01010101010101010").is_err());
    assert!(parse_key("0000000000000000").is_err());
}

#[test]
fn test_key_checksum() {
    assert!(key_checksum(&[
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true
    ]));
    assert!(!key_checksum(&[
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        false, false, false, false, false, false, false, true,
        true, false, false, false, false, false, false, true
    ]));
}

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

#[test]
fn test_pc1() {
    assert_eq!(pc1(&(1..=64).into_iter().collect::<Vec<_>>().try_into().unwrap()),
               [
                   57, 49, 41, 33, 25, 17, 9,
                   1, 58, 50, 42, 34, 26, 18,
                   10, 2, 59, 51, 43, 35, 27,
                   19, 11, 3, 60, 52, 44, 36,
                   63, 55, 47, 39, 31, 23, 15,
                   7, 62, 54, 46, 38, 30, 22,
                   14, 6, 61, 53, 45, 37, 29,
                   21, 13, 5, 28, 20, 12, 4
               ]);
}

#[test]
fn test_pc2() {
    assert_eq!(pc2(&(1..=56).into_iter().collect::<Vec<_>>().try_into().unwrap()),
               [
                   14, 17, 11, 24, 1, 5,
                   3, 28, 15, 6, 21, 10,
                   23, 19, 12, 4, 26, 8,
                   16, 7, 27, 20, 13, 2,
                   41, 52, 31, 37, 47, 55,
                   30, 40, 51, 45, 33, 48,
                   44, 49, 39, 56, 34, 53,
                   46, 42, 50, 36, 29, 32
               ]);
}

#[test]
fn test_rotate_left() {
    let mut vec = (0..10).collect::<Vec<_>>();
    rotate_left(&mut vec, 1);
    assert_eq!(vec, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);

    let mut vec = (0..10).collect::<Vec<_>>();
    rotate_left(&mut vec, 2);
    assert_eq!(vec, vec![2, 3, 4, 5, 6, 7, 8, 9, 0, 1]);

    let mut vec = (0..10).collect::<Vec<_>>();
    rotate_left(&mut vec, 9);
    assert_eq!(vec, vec![9, 0, 1, 2, 3, 4, 5, 6, 7, 8]);

    let mut vec = (0..10).collect::<Vec<_>>();
    rotate_left(&mut vec, 0);
    assert_eq!(vec, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

    let mut vec = (0..10).collect::<Vec<_>>();
    rotate_left(&mut vec, 10);
    assert_eq!(vec, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

    let mut vec = (0..10).collect::<Vec<_>>();
    rotate_left(&mut vec[2..5], 1);
    assert_eq!(vec, vec![0, 1, 3, 4, 2, 5, 6, 7, 8, 9]);

    let mut vec = (0..10).collect::<Vec<_>>();
    rotate_left(&mut vec[2..5], 2);
    assert_eq!(vec, vec![0, 1, 4, 2, 3, 5, 6, 7, 8, 9]);

    let mut vec = (0..10).collect::<Vec<_>>();
    rotate_left(&mut vec[2..5], 0);
    assert_eq!(vec, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

    let mut vec = (0..10).collect::<Vec<_>>();
    rotate_left(&mut vec[2..5], 3);
    assert_eq!(vec, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
}

#[test]
fn test_generate_sub_key() {
    let key = (0..64).into_iter().collect::<Vec<_>>().try_into().unwrap();
    let mut cd = pc1(&key);
    let expect = [
        {
            rotate_left(&mut cd[0..28], 1);
            rotate_left(&mut cd[28..56], 1);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 1);
            rotate_left(&mut cd[28..56], 1);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 1);
            rotate_left(&mut cd[28..56], 1);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 2);
            rotate_left(&mut cd[28..56], 2);
            pc2(&cd)
        },
        {
            rotate_left(&mut cd[0..28], 1);
            rotate_left(&mut cd[28..56], 1);
            pc2(&cd)
        }
    ];
    let sub_key = generate_sub_key(&key);
    assert_eq!(sub_key, expect);
}

#[test]
fn test_ip() {
    let input = (1..=64).into_iter().collect::<Vec<_>>().try_into().unwrap();
    assert_eq!(
        ip(&input),
        [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        ]
    );
    assert_eq!(ip_inverse(&ip(&input)), input);
}

#[test]
fn test_ip_inverse() {
    let input = (1..=64).into_iter().collect::<Vec<_>>().try_into().unwrap();
    assert_eq!(
        ip_inverse(&input),
        [
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        ]
    );
    assert_eq!(ip(&ip_inverse(&input)), input)
}

#[test]
fn test_e() {
    assert_eq!(
        e(&(1..=32).into_iter().collect::<Vec<_>>().try_into().unwrap()),
        [
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        ]
    )
}

#[test]
fn test_p() {
    assert_eq!(
        p(&(1..=32).into_iter().collect::<Vec<_>>().try_into().unwrap()),
        [
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25,
        ]
    );
}

#[test]
fn test_to_bool() {}

#[test]
fn test_s() {
    let mut result = [false; 4];
    s(0, &[false, true, true, false, false, true], &mut result);
    assert_eq!(result, [true, false, false, true]);

    s(4, &[false, true, true, false, false, true], &mut result);
    assert_eq!(result, [false, false, true, true]);

    s(5, &[true, false, true, true, false, false], &mut result);
    assert_eq!(result, [true, true, false, false]);

    let mut count = [0; 16];
    for i in 0..6 {
        for j in 0..1 << 6 {
            let input = [
                (j & 0b100000) != 0,
                (j & 0b010000) != 0,
                (j & 0b001000) != 0,
                (j & 0b000100) != 0,
                (j & 0b000010) != 0,
                (j & 0b000001) != 0,
            ];
            s(i, &input, &mut result);
            let index =
                if result[0] { 1 } else { 0 } << 3 |
                    if result[1] { 1 } else { 0 } << 2 |
                    if result[2] { 1 } else { 0 } << 1 |
                    if result[3] { 1 } else { 0 };
            count[index] += 1;
        }
    }
    for i in &count {
        assert_eq!(*i, (1 << 6) * 6 / 16);
    }
}

#[test]
fn test_pick_64bit_from_slice() {
    let vec = vec![0, 1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(
        pick_64bit_from_slice(&vec[..]),
        [
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, true,
            false, false, false, false, false, false, true, false,
            false, false, false, false, false, false, true, true,
            false, false, false, false, false, true, false, false,
            false, false, false, false, false, true, false, true,
            false, false, false, false, false, true, true, false,
            false, false, false, false, false, true, true, true,
        ]
    );
    assert_eq!(
        pick_64bit_from_slice(&vec[8..]),
        [
            false, false, false, false, true, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
            false, false, false, false, false, false, false, false,
        ]
    );
}

#[test]
fn test_push_64bit() {
    let mut vec = Vec::new();
    push_64bit(&mut vec,
               [
                   false, false, false, false, false, false, false, false,
                   false, false, false, false, false, false, false, true,
                   false, false, false, false, false, false, true, false,
                   false, false, false, false, false, false, true, true,
                   false, false, false, false, false, true, false, false,
                   false, false, false, false, false, true, false, true,
                   false, false, false, false, false, true, true, false,
                   false, false, false, false, false, true, true, true,
               ]);
    assert_eq!(vec, vec![0, 1, 2, 3, 4, 5, 6, 7]);

    push_64bit(&mut vec,
               [
                   false, false, false, false, true, false, false, false,
                   false, false, false, false, false, false, false, false,
                   false, false, false, false, false, false, false, false,
                   false, false, false, false, false, false, false, false,
                   false, false, false, false, false, false, false, false,
                   false, false, false, false, false, false, false, false,
                   false, false, false, false, false, false, false, false,
                   false, false, false, false, false, false, false, false,
               ]);
    assert_eq!(vec, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn test_keygen() {
    for _ in 0..100 {
        assert!(key_checksum(&keygen()));
    }
}

#[test]
fn test_encrypt_decrypt() {
    for _ in 0..100 {
        let key = keygen();
        let mut rng = thread_rng();
        let length = rng.gen_range(1, 128);
        let mut input = Vec::with_capacity(length);
        for _ in 0..length {
            input.push(rng.gen());
        }
        let encrypted = encrypt(input.clone(), &key);
        input.resize((input.len() + 7) & !7, 0);
        assert_eq!(decrypt(encrypted, &key), input);
    }
}
