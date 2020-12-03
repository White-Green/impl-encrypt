use super::{decrypt, encrypt, Key};

#[test]
fn test_key() {
    assert_eq!(Key::new("1 0 2"), Ok(Key(vec![1, 0, 2])));
    Key::new("").unwrap_err();
    Key::new("0 0 2").unwrap_err();
    Key::new("0 2 3").unwrap_err();

    assert_eq!(Key::new("2 0 3 1").unwrap().small(3), Key(vec![2, 0, 1]));
    assert_eq!(Key::new("2 0 3 1").unwrap().inverse(), Key(vec![1, 3, 0, 2]));
}

#[test]
fn test_encrypt() {
    assert_eq!(encrypt("TranspositionCipher", &Key::new("2 0 3 1").unwrap()), Ok("rnTapssotoiiCpnierh".to_string()))
}

#[test]
fn test_decrypt() {
    assert_eq!(decrypt("rnTapssotoiiCpnierh", &Key::new("2 0 3 1").unwrap()), Ok("TranspositionCipher".to_string()))
}