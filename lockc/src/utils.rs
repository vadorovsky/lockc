use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HashError {
    #[error("could not convert the hash to a byte array")]
    ByteWriteError(#[from] io::Error),
}

/// Simple string hash function which allows to use strings as keys for BPF
/// maps even though they use u32 as a key type.
pub fn hash(s: &str) -> Result<u32, HashError> {
    let mut hash: u32 = 0;

    for c in s.chars() {
        let c_u32 = c as u32;
        hash += c_u32;
    }

    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_should_return_hash_when_correct() {
        let test_string = "Test string for hash function";
        assert!(hash(test_string).is_ok());
        let returned_hash = hash(test_string).unwrap();
        let correct_hash: u32 = 2824;
        assert_eq!(returned_hash, correct_hash);
    }
}
