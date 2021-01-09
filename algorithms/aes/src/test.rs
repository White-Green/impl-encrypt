use super::*;

#[test]
fn test_key_as_slice() {
    assert_eq!(Key::AES128([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]).as_slice(),
               &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    assert_eq!(Key::AES192([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]).as_slice(),
               &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23]);
    assert_eq!(Key::AES256([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]).as_slice(),
               &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]);
}

#[test]
fn test_test_keygen() {
    assert_eq!(keygen_128().as_slice().len(), 128 / 8);
    assert_eq!(keygen_192().as_slice().len(), 192 / 8);
    assert_eq!(keygen_256().as_slice().len(), 256 / 8);

    assert_ne!(keygen_128(), keygen_128());
    assert_ne!(keygen_192(), keygen_192());
    assert_ne!(keygen_256(), keygen_256());
}

#[test]
fn test_parse_key() {
    assert_eq!(parse_key("000102030405060708090a0b0c0d0e0f"),
               Ok(Key::AES128([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])));
    assert_eq!(parse_key("000102030405060708090a0b0c0d0e0f1011121314151617"),
               Ok(Key::AES192([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23])));
    assert_eq!(parse_key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
               Ok(Key::AES256([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31])));

    assert!(parse_key("000102030405060708090a0b0c0d0e0f1").is_err());
    assert!(parse_key("000102030405060708090a0b0c0d0e0").is_err());
    assert!(parse_key("000102030405060708090a0b0c0d0e0f10111213141516171").is_err());
    assert!(parse_key("000102030405060708090a0b0c0d0e0f101112131415161").is_err());
    assert!(parse_key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0").is_err());
    assert!(parse_key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1").is_err());

    assert!(parse_key("g000102030405060708090a0b0c0d0e0").is_err());
}

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

#[test]
fn test_polynomial_mul() {
    assert_eq!(Polynomial(0b0000_0001) * Polynomial(0b0000_0001), Polynomial(0b0000_0001));
    assert_eq!(Polynomial(0b0000_0001) * Polynomial(0b0000_0010), Polynomial(0b0000_0010));
    assert_eq!(Polynomial(0b0000_0001) * Polynomial(0b0000_0100), Polynomial(0b0000_0100));
    assert_eq!(Polynomial(0b0000_0001) * Polynomial(0b0000_1000), Polynomial(0b0000_1000));
    assert_eq!(Polynomial(0b0000_0001) * Polynomial(0b0001_0000), Polynomial(0b0001_0000));
    assert_eq!(Polynomial(0b0000_0001) * Polynomial(0b0010_0000), Polynomial(0b0010_0000));
    assert_eq!(Polynomial(0b0000_0001) * Polynomial(0b0100_0000), Polynomial(0b0100_0000));
    assert_eq!(Polynomial(0b0000_0001) * Polynomial(0b1000_0000), Polynomial(0b1000_0000));

    assert_eq!(Polynomial(0b0000_0010) * Polynomial(0b0000_0001), Polynomial(0b0000_0010));
    assert_eq!(Polynomial(0b0000_0010) * Polynomial(0b0000_0010), Polynomial(0b0000_0100));
    assert_eq!(Polynomial(0b0000_0010) * Polynomial(0b0000_0100), Polynomial(0b0000_1000));
    assert_eq!(Polynomial(0b0000_0010) * Polynomial(0b0000_1000), Polynomial(0b0001_0000));
    assert_eq!(Polynomial(0b0000_0010) * Polynomial(0b0001_0000), Polynomial(0b0010_0000));
    assert_eq!(Polynomial(0b0000_0010) * Polynomial(0b0010_0000), Polynomial(0b0100_0000));
    assert_eq!(Polynomial(0b0000_0010) * Polynomial(0b0100_0000), Polynomial(0b1000_0000));
    assert_eq!(Polynomial(0b0000_0010) * Polynomial(0b1000_0000), Polynomial(0b0001_1011));

    assert_eq!(Polynomial(0b0000_0100) * Polynomial(0b0000_0001), Polynomial(0b0000_0100));
    assert_eq!(Polynomial(0b0000_0100) * Polynomial(0b0000_0010), Polynomial(0b0000_1000));
    assert_eq!(Polynomial(0b0000_0100) * Polynomial(0b0000_0100), Polynomial(0b0001_0000));
    assert_eq!(Polynomial(0b0000_0100) * Polynomial(0b0000_1000), Polynomial(0b0010_0000));
    assert_eq!(Polynomial(0b0000_0100) * Polynomial(0b0001_0000), Polynomial(0b0100_0000));
    assert_eq!(Polynomial(0b0000_0100) * Polynomial(0b0010_0000), Polynomial(0b1000_0000));
    assert_eq!(Polynomial(0b0000_0100) * Polynomial(0b0100_0000), Polynomial(0b0001_1011));
    assert_eq!(Polynomial(0b0000_0100) * Polynomial(0b1000_0000), Polynomial(0b0011_0110));

    assert_eq!(Polynomial(0b0000_1000) * Polynomial(0b0000_0001), Polynomial(0b0000_1000));
    assert_eq!(Polynomial(0b0000_1000) * Polynomial(0b0000_0010), Polynomial(0b0001_0000));
    assert_eq!(Polynomial(0b0000_1000) * Polynomial(0b0000_0100), Polynomial(0b0010_0000));
    assert_eq!(Polynomial(0b0000_1000) * Polynomial(0b0000_1000), Polynomial(0b0100_0000));
    assert_eq!(Polynomial(0b0000_1000) * Polynomial(0b0001_0000), Polynomial(0b1000_0000));
    assert_eq!(Polynomial(0b0000_1000) * Polynomial(0b0010_0000), Polynomial(0b0001_1011));
    assert_eq!(Polynomial(0b0000_1000) * Polynomial(0b0100_0000), Polynomial(0b0011_0110));
    assert_eq!(Polynomial(0b0000_1000) * Polynomial(0b1000_0000), Polynomial(0b0110_1100));

    assert_eq!(Polynomial(0b0001_0000) * Polynomial(0b0000_0001), Polynomial(0b0001_0000));
    assert_eq!(Polynomial(0b0001_0000) * Polynomial(0b0000_0010), Polynomial(0b0010_0000));
    assert_eq!(Polynomial(0b0001_0000) * Polynomial(0b0000_0100), Polynomial(0b0100_0000));
    assert_eq!(Polynomial(0b0001_0000) * Polynomial(0b0000_1000), Polynomial(0b1000_0000));
    assert_eq!(Polynomial(0b0001_0000) * Polynomial(0b0001_0000), Polynomial(0b0001_1011));
    assert_eq!(Polynomial(0b0001_0000) * Polynomial(0b0010_0000), Polynomial(0b0011_0110));
    assert_eq!(Polynomial(0b0001_0000) * Polynomial(0b0100_0000), Polynomial(0b0110_1100));
    assert_eq!(Polynomial(0b0001_0000) * Polynomial(0b1000_0000), Polynomial(0b1101_1000));

    assert_eq!(Polynomial(0b0010_0000) * Polynomial(0b0000_0001), Polynomial(0b0010_0000));
    assert_eq!(Polynomial(0b0010_0000) * Polynomial(0b0000_0010), Polynomial(0b0100_0000));
    assert_eq!(Polynomial(0b0010_0000) * Polynomial(0b0000_0100), Polynomial(0b1000_0000));
    assert_eq!(Polynomial(0b0010_0000) * Polynomial(0b0000_1000), Polynomial(0b0001_1011));
    assert_eq!(Polynomial(0b0010_0000) * Polynomial(0b0001_0000), Polynomial(0b0011_0110));
    assert_eq!(Polynomial(0b0010_0000) * Polynomial(0b0010_0000), Polynomial(0b0110_1100));
    assert_eq!(Polynomial(0b0010_0000) * Polynomial(0b0100_0000), Polynomial(0b1101_1000));
    assert_eq!(Polynomial(0b0010_0000) * Polynomial(0b1000_0000), Polynomial(0b1010_1011));

    assert_eq!(Polynomial(0b0100_0000) * Polynomial(0b0000_0001), Polynomial(0b0100_0000));
    assert_eq!(Polynomial(0b0100_0000) * Polynomial(0b0000_0010), Polynomial(0b1000_0000));
    assert_eq!(Polynomial(0b0100_0000) * Polynomial(0b0000_0100), Polynomial(0b0001_1011));
    assert_eq!(Polynomial(0b0100_0000) * Polynomial(0b0000_1000), Polynomial(0b0011_0110));
    assert_eq!(Polynomial(0b0100_0000) * Polynomial(0b0001_0000), Polynomial(0b0110_1100));
    assert_eq!(Polynomial(0b0100_0000) * Polynomial(0b0010_0000), Polynomial(0b1101_1000));
    assert_eq!(Polynomial(0b0100_0000) * Polynomial(0b0100_0000), Polynomial(0b1010_1011));
    assert_eq!(Polynomial(0b0100_0000) * Polynomial(0b1000_0000), Polynomial(0b0100_1101));

    assert_eq!(Polynomial(0b1000_0000) * Polynomial(0b0000_0001), Polynomial(0b1000_0000));
    assert_eq!(Polynomial(0b1000_0000) * Polynomial(0b0000_0010), Polynomial(0b0001_1011));
    assert_eq!(Polynomial(0b1000_0000) * Polynomial(0b0000_0100), Polynomial(0b0011_0110));
    assert_eq!(Polynomial(0b1000_0000) * Polynomial(0b0000_1000), Polynomial(0b0110_1100));
    assert_eq!(Polynomial(0b1000_0000) * Polynomial(0b0001_0000), Polynomial(0b1101_1000));
    assert_eq!(Polynomial(0b1000_0000) * Polynomial(0b0010_0000), Polynomial(0b1010_1011));
    assert_eq!(Polynomial(0b1000_0000) * Polynomial(0b0100_0000), Polynomial(0b0100_1101));
    assert_eq!(Polynomial(0b1000_0000) * Polynomial(0b1000_0000), Polynomial(0b1001_1010));

    assert_eq!(Polynomial(0b1000_0011) * Polynomial(0b0010_1100), Polynomial(0b1000_0101)); //"(+x^0+x^1+x^7)*(+x^2+x^3+x^5)"
    assert_eq!(Polynomial(0b1011_0110) * Polynomial(0b1000_1000), Polynomial(0b0000_0011)); //"(+x^1+x^2+x^4+x^5+x^7)*(+x^3+x^7)"
    assert_eq!(Polynomial(0b0001_0101) * Polynomial(0b0000_1011), Polynomial(0b1001_0111)); //"(+x^0+x^2+x^4)*(+x^0+x^1+x^3)"
    assert_eq!(Polynomial(0b1111_1110) * Polynomial(0b1011_1000), Polynomial(0b1101_1111)); //"(+x^1+x^2+x^3+x^4+x^5+x^6+x^7)*(+x^3+x^4+x^5+x^7)"
    assert_eq!(Polynomial(0b0110_1001) * Polynomial(0b0000_1100), Polynomial(0b1101_1010)); //"(+x^0+x^3+x^5+x^6)*(+x^2+x^3)";
    assert_eq!(Polynomial(0b1011_0001) * Polynomial(0b0010_0010), Polynomial(0b1010_1000)); //"(+x^0+x^4+x^5+x^7)*(+x^1+x^5)";
    assert_eq!(Polynomial(0b0010_1010) * Polynomial(0b0110_1101), Polynomial(0b1001_0000)); //"(+x^1+x^3+x^5)*(+x^0+x^2+x^3+x^5+x^6)";
    assert_eq!(Polynomial(0b0011_0011) * Polynomial(0b0110_0010), Polynomial(0b0010_1000)); //"(+x^0+x^1+x^4+x^5)*(+x^1+x^5+x^6)";
    assert_eq!(Polynomial(0b1110_1011) * Polynomial(0b1011_0011), Polynomial(0b1111_1011)); //"(+x^0+x^1+x^3+x^5+x^6+x^7)*(+x^0+x^1+x^4+x^5+x^7)";
    assert_eq!(Polynomial(0b0100_1000) * Polynomial(0b0011_1101), Polynomial(0b0010_1010)); //"(+x^3+x^6)*(+x^0+x^2+x^3+x^4+x^5)";
    assert_eq!(Polynomial(0b0011_0010) * Polynomial(0b1011_0001), Polynomial(0b0100_1101)); //"(+x^1+x^4+x^5)*(+x^0+x^4+x^5+x^7)";
    assert_eq!(Polynomial(0b1011_1010) * Polynomial(0b0110_1100), Polynomial(0b1001_1100)); //"(+x^1+x^3+x^4+x^5+x^7)*(+x^2+x^3+x^5+x^6)";
    assert_eq!(Polynomial(0b1111_0011) * Polynomial(0b1111_1101), Polynomial(0b1000_0110)); //"(+x^0+x^1+x^4+x^5+x^6+x^7)*(+x^0+x^2+x^3+x^4+x^5+x^6+x^7)";
    assert_eq!(Polynomial(0b0101_0101) * Polynomial(0b1000_1001), Polynomial(0b1110_1000)); //"(+x^0+x^2+x^4+x^6)*(+x^0+x^3+x^7)";
    assert_eq!(Polynomial(0b0110_1111) * Polynomial(0b1000_0100), Polynomial(0b1000_0000)); //"(+x^0+x^1+x^2+x^3+x^5+x^6)*(+x^2+x^7)";
    assert_eq!(Polynomial(0b0011_1100) * Polynomial(0b0000_1101), Polynomial(0b0011_0111)); //"(+x^2+x^3+x^4+x^5)*(+x^0+x^2+x^3)";

    assert_eq!(Polynomial(0b1111_1111)*Polynomial(0b1111_1111),Polynomial(0b0001_0011)); //"(+x^0+x^1+x^2+x^3+x^4+x^5+x^6+x^7)*(+x^0+x^1+x^2+x^3+x^4+x^5+x^6+x^7)"
}

#[test]
fn test_rot_word() {
    assert_eq!(rot_word(0x01020304), 0x02030401);
}

#[test]
fn test_sub_key_transpose() {
    assert_eq!(
        SubKey::AES128([
            [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f],
            [0x00102030, 0x40506070, 0x8090a0b0, 0xc0d0e0f0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0]
        ]).transpose(),
        vec![
            [0x0004080c, 0x0105090d, 0x02060a0e, 0x03070b0f],
            [0x004080c0, 0x105090d0, 0x2060a0e0, 0x3070b0f0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0],
            [0, 0, 0, 0]
        ]);
}

#[test]
fn test_sub_byte() {
    assert_eq!(sub_byte(0x00), 0x63);
    assert_eq!(sub_byte(0x31), 0xc7);
    assert_eq!(sub_byte(0x12), 0xc9);
    assert_eq!(sub_byte(0x9a), 0xb8);
}

#[test]
fn test_sub_bytes() {
    let mut state = [
        0x00_31_12_9a,
        0x31_12_9a_00,
        0x12_9a_00_31,
        0x9a_00_31_12,
    ];
    sub_bytes(&mut state);
    assert_eq!(state, [
        0x63_c7_c9_b8,
        0xc7_c9_b8_63,
        0xc9_b8_63_c7,
        0xb8_63_c7_c9,
    ])
}

#[test]
fn test_shift_rows() {
    let mut state = [
        0x00_01_02_03,
        0x04_05_06_07,
        0x08_09_0a_0b,
        0x0c_0d_0e_0f,
    ];
    shift_rows(&mut state);
    assert_eq!(state, [
        0x00_01_02_03,
        0x05_06_07_04,
        0x0a_0b_08_09,
        0x0f_0c_0d_0e,
    ]);

    let mut state = [
        0x00_10_20_30,
        0x40_50_60_70,
        0x80_90_a0_b0,
        0xc0_d0_e0_f0,
    ];
    shift_rows(&mut state);
    assert_eq!(state, [
        0x00_10_20_30,
        0x50_60_70_40,
        0xa0_b0_80_90,
        0xf0_c0_d0_e0,
    ]);
}

#[test]
fn test_mix_columns() {
    let mut state = [
        0x01_01_10_01,
        0x01_02_20_01,
        0x01_03_40_01,
        0x01_04_80_01];
    mix_columns(&mut state);
    assert_eq!(state, [
        0x01_03_80_01,
        0x01_04_10_01,
        0x01_09_2b_01,
        0x01_0a_4b_01
    ]);
}

#[test]
fn test_add_round_key() {
    let mut state = [
        0x00_01_02_03,
        0x04_05_06_07,
        0x08_09_0a_0b,
        0x0c_0d_0e_0f,
    ];
    add_round_key(&mut state, &[0x33333333, 0xcccccccc, 0x55555555, 0xaaaaaaaa]);
    assert_eq!(state, [
        0x00_01_02_03 ^ 0x33333333,
        0x04_05_06_07 ^ 0xcccccccc,
        0x08_09_0a_0b ^ 0x55555555,
        0x0c_0d_0e_0f ^ 0xaaaaaaaa,
    ]);
}

#[test]
fn test_inv_add_round_key() {
    let mut state = [
        0x00_01_02_03,
        0x04_05_06_07,
        0x08_09_0a_0b,
        0x0c_0d_0e_0f,
    ];
    inv_add_round_key(&mut state, &[0x33333333, 0xcccccccc, 0x55555555, 0xaaaaaaaa]);
    assert_eq!(state, [
        0x00_01_02_03 ^ 0x33333333,
        0x04_05_06_07 ^ 0xcccccccc,
        0x08_09_0a_0b ^ 0x55555555,
        0x0c_0d_0e_0f ^ 0xaaaaaaaa,
    ]);
}

#[test]
fn test_inv_mix_columns() {
    let mut state = [
        0x01_03_80_01,
        0x01_04_10_01,
        0x01_09_2b_01,
        0x01_0a_4b_01];
    inv_mix_columns(&mut state);
    assert_eq!(state, [
        0x01_01_10_01,
        0x01_02_20_01,
        0x01_03_40_01,
        0x01_04_80_01
    ])
}

#[test]
fn test_inv_shift_rows() {
    let mut state = [
        0x00_01_02_03,
        0x05_06_07_04,
        0x0a_0b_08_09,
        0x0f_0c_0d_0e,
    ];
    inv_shift_rows(&mut state);
    assert_eq!(state, [
        0x00_01_02_03,
        0x04_05_06_07,
        0x08_09_0a_0b,
        0x0c_0d_0e_0f,
    ]);

    let mut state = [
        0x00_10_20_30,
        0x50_60_70_40,
        0xa0_b0_80_90,
        0xf0_c0_d0_e0,
    ];
    inv_shift_rows(&mut state);
    assert_eq!(state, [
        0x00_10_20_30,
        0x40_50_60_70,
        0x80_90_a0_b0,
        0xc0_d0_e0_f0,
    ]);
}

#[test]
fn test_inv_sub_bytes() {
    let mut state = [
        0x63_c7_c9_b8,
        0xc7_c9_b8_63,
        0xc9_b8_63_c7,
        0xb8_63_c7_c9,
    ];
    inv_sub_bytes(&mut state);
    assert_eq!(state, [
        0x00_31_12_9a,
        0x31_12_9a_00,
        0x12_9a_00_31,
        0x9a_00_31_12,
    ])
}

#[test]
fn test_pick_state_from_slice() {
    assert_eq!(pick_state_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
               [
                   0x00_04_08_0c,
                   0x01_05_09_0d,
                   0x02_06_0a_0e,
                   0x03_07_0b_0f]);

    assert_eq!(pick_state_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
               [
                   0x00_04_08_00,
                   0x01_05_09_00,
                   0x02_06_00_00,
                   0x03_07_00_00]);
}

#[test]
fn test_push_state() {
    let mut vec = Vec::new();
    push_state(&mut vec, [0x00_04_08_0c,
        0x01_05_09_0d,
        0x02_06_0a_0e,
        0x03_07_0b_0f]);
    assert_eq!(vec, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
}

#[test]
fn test_encrypt_decrypt() {
    fn test(key: Key) {
        let mut rng = thread_rng();
        let length = rng.gen_range(1, 128);
        let mut input = Vec::with_capacity(length);
        for _ in 0..length {
            input.push(rng.gen());
        }
        let encrypted = encrypt(input.clone(), &key);
        input.resize((input.len() + 15) & !15, 0);
        assert_eq!(decrypt(encrypted, &key), input);
    }
    for _ in 0..32 {
        test(keygen_128());
    }
    for _ in 0..32 {
        test(keygen_192());
    }
    for _ in 0..32 {
        test(keygen_256());
    }
}
