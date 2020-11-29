use std::iter::FromIterator;

use super::{decrypt, encrypt};

#[test]
fn test_encrypt() {
    assert!(encrypt("abcdefghijklmnopqrstuvwxyz", 3).unwrap().chars().zip("ajsbktcludmvenwfoxgpyhqzir-".chars()).all(|(a, b)| b == '-' || a == b));
    assert!(encrypt("abcdefghijklmnopqrstuvwxyz", 5).unwrap().chars().zip("agmsybhntzciou-djpv-ekqw-flrx-".chars()).all(|(a, b)| b == '-' || a == b));
}

#[test]
fn test_decrypt() {
    assert_eq!(String::from_iter(decrypt("ajsbktcludmvenwfoxgpyhqzir-", 3).unwrap().chars()), "abcdefghijklmnopqrstuvwxyz-".to_string());
    assert_eq!(String::from_iter(decrypt("agmsybhntzciou-djpv-ekqw-flrx-", 5).unwrap().chars()), "abcdefghijklmnopqrstuvwxyz----".to_string());
}