use anyhow::{ensure, Result};
use itertools::Itertools;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Rc4Key {
    s: [u8; 256],
    i: usize,
    j: usize
}

impl Rc4Key {
    pub fn new(key: &[u8]) -> Result<Rc4Key> {
        ensure!(key.len() >= 1);
        ensure!(key.len() <= 256);
        let mut s = [0u8; 256];
        for (idx, val) in s.iter_mut().enumerate() {
            *val = idx as u8;
        }
        let mut j : usize = 0;
        for i in 0..256usize {
            j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
            (s[i], s[j]) = (s[j], s[i]);
        }
        Ok(
            Rc4Key{s, i: 0, j: 0}
        )
    }

    pub fn next_byte(&mut self) -> u8 {
        self.i += 1;
        self.j = (self.j  + (self.s[self.i] as usize)) % 256;
        (self.s[self.i], self.s[self.j]) = (self.s[self.j], self.s[self.i]);
        let k_idx = self.s[self.i].wrapping_add(self.s[self.j]);
        self.s[k_idx as usize]
    }

    pub fn crypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|b| b ^ self.next_byte()).collect_vec()
    }
}

#[cfg(test)]
mod tests {
    use hex::ToHex;

    use super::*;

    #[test]
    pub fn rc4_kats() -> Result<()> {
        let mut key = Rc4Key::new(b"Key")?;
        let ciphertext = key.crypt(b"Plaintext").encode_hex_upper::<String>();
        assert_eq!("BBF316E8D940AF0AD3", ciphertext);

        let mut key = Rc4Key::new(b"Wiki")?;
        let ciphertext = key.crypt(b"pedia").encode_hex_upper::<String>();
        assert_eq!("1021BF0420", ciphertext);

        let mut key = Rc4Key::new(b"Secret")?;
        let ciphertext = key.crypt(b"Attack at dawn").encode_hex_upper::<String>();
        assert_eq!("45A01F645FC35B383552544B9BF5", ciphertext);
        Ok(())
    }
}