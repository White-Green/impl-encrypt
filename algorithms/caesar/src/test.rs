use super::{encrypt, decrypt};

#[test]
fn test_encrypt() {
    assert_eq!(encrypt("abcdefghijklmnopqrstuvwxyz", 3), Ok("defghijklmnopqrstuvwxyzabc".to_string()));
    assert_eq!(encrypt("abcdefghijklmnopqrstuvwxyz", 5), Ok("fghijklmnopqrstuvwxyzabcde".to_string()));
    encrypt("A", 5).unwrap_err();
    encrypt("0", 5).unwrap_err();
    encrypt("+", 5).unwrap_err();
    encrypt("/", 5).unwrap_err();
    encrypt("!", 5).unwrap_err();
}

#[test]
fn test_decrypt(){
    assert_eq!(decrypt("defghijklmnopqrstuvwxyzabc", 3), Ok("abcdefghijklmnopqrstuvwxyz".to_string()));
    assert_eq!(decrypt("fghijklmnopqrstuvwxyzabcde", 5), Ok("abcdefghijklmnopqrstuvwxyz".to_string()));
    decrypt("A", 5).unwrap_err();
    decrypt("0", 5).unwrap_err();
    decrypt("+", 5).unwrap_err();
    decrypt("/", 5).unwrap_err();
    decrypt("!", 5).unwrap_err();
}