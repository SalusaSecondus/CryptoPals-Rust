use std::{cell::RefCell, collections::HashMap};

use anyhow::{ensure, Context, Result};
use lazy_static::lazy_static;
use rand::distributions::{Distribution, Uniform};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use std::{thread, time};
use time::{SystemTime, UNIX_EPOCH};

use crate::padding::Padding;
use crate::{aes::AesKey, prng::MT19937};

pub struct Challenge11Oracle();

impl Challenge11Oracle {
    pub fn encrypt(plaintext: &[u8]) -> Result<(Vec<u8>, bool)> {
        lazy_static! {
            static ref EXTRA_RANGE: Uniform<usize> = Uniform::new_inclusive(5, 10);
            static ref KEY: AesKey = {
                let mut raw_key = [0u8; 16];
                OsRng.fill_bytes(&mut raw_key);
                AesKey::new(&raw_key).unwrap()
            };
            static ref IV: [u8; 16] = [0; 16];
        }
        let mut rng = OsRng::default();

        let mut extra = vec![];
        extra.resize(EXTRA_RANGE.sample(&mut rng), 0u8);
        rng.fill_bytes(&mut extra);

        let mut result: Vec<u8> = vec![];
        result.extend(extra.iter());
        result.extend(plaintext.iter());

        extra.resize(EXTRA_RANGE.sample(&mut rng), 0u8);
        rng.fill_bytes(&mut extra);
        result.extend(extra.iter());

        let result = Padding::Pkcs7Padding(16).pad(&result)?;

        let use_cbc: bool = rng.gen();
        let result = if use_cbc {
            KEY.encrypt_cbc(&IV[..], &result)?
        } else {
            KEY.encrypt_ecb(&result)?
        };
        Ok((result, use_cbc))
    }
}

pub struct Set2Oracle {
    key: AesKey,
    prefix: Vec<u8>,
    rng: RefCell<OsRng>,
}

impl Set2Oracle {
    pub fn new() -> Set2Oracle {
        let mut raw_key = [0u8; 16];
        OsRng.fill_bytes(&mut raw_key);
        let key = AesKey::new(&raw_key).unwrap();

        let prefix_range = Uniform::new_inclusive(5, 10);
        let mut prefix = vec![];
        prefix.resize_with(prefix_range.sample(&mut OsRng), || OsRng.gen());

        Set2Oracle {
            key,
            prefix,
            rng: RefCell::new(OsRng),
        }
    }

    pub fn encrypt12(&self, prefix: &[u8]) -> Result<Vec<u8>> {
        lazy_static! {
            static ref HIDDEN_PT: Vec<u8> = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        }

        let mut plaintext = Vec::from(prefix);
        plaintext.extend(HIDDEN_PT.iter());

        let padded = Padding::Pkcs7Padding(16).pad(&plaintext)?;
        Ok(self.key.encrypt_ecb(&padded)?)
    }

    pub fn encrypt14(&self, attacker_controlled: &[u8]) -> Result<Vec<u8>> {
        lazy_static! {
            static ref HIDDEN_PT: Vec<u8> = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        }

        let mut plaintext = self.prefix.clone();
        plaintext.extend(attacker_controlled);
        plaintext.extend(HIDDEN_PT.iter());

        let padded = Padding::Pkcs7Padding(16).pad(&plaintext)?;
        Ok(self.key.encrypt_ecb(&padded)?)
    }

    pub fn is_admin_13(&self, ciphertext: &[u8]) -> bool {
        let invalid_str = String::from("invalid");
        self.key
            .decrypt_ecb(ciphertext)
            .and_then(|pt| Padding::Pkcs7Padding(16).unpad(&pt))
            .and_then(|pt| String::from_utf8(pt).context("Bad UTF8"))
            .and_then(|pt| Set2Oracle::parse_kv(&pt, '&'))
            .map(|m| m.get("role").unwrap_or(&invalid_str) == "admin")
            .unwrap_or(false)
    }

    pub fn get_role_13(&self, ciphertext: &[u8]) -> Result<String> {
        let invalid_str = String::from("invalid");
        self.key
            .decrypt_ecb(ciphertext)
            .and_then(|pt| Padding::Pkcs7Padding(16).unpad(&pt))
            .and_then(|pt| String::from_utf8(pt).context("Bad UTF8"))
            .and_then(|pt| Set2Oracle::parse_kv(&pt, '&'))
            .map(|m| m.get("role").unwrap_or(&invalid_str).to_owned())
    }

    pub fn profile_for_13(&self, email: &str) -> Result<Vec<u8>> {
        ensure!(!email.contains('&'), "Email contains invalid character");
        ensure!(!email.contains('='), "Email contains invalid character");

        let mut pt: Vec<u8> = Vec::from(&b"email="[..]);
        pt.extend(email.as_bytes().iter());
        pt.extend_from_slice(b"&uid=10&role=user");

        self.key.encrypt_ecb(&Padding::Pkcs7Padding(16).pad(&pt)?)
    }

    fn parse_kv(s: &str, pair_delimiter: char) -> Result<HashMap<String, String>> {
        let mut result = HashMap::new();
        for pairs in s.split(pair_delimiter) {
            let mut parts = pairs.splitn(2, '=');
            let key = parts.next().context("Missing key")?;
            let value = parts.next().context("Missing value")?;

            result.insert(key.to_owned(), value.to_owned());
        }
        Ok(result)
    }

    pub fn encrypt_16(&self, user_data: &str) -> Result<Vec<u8>> {
        ensure!(
            !user_data.contains(';'),
            "user_data contains invalid character"
        );
        ensure!(
            !user_data.contains('='),
            "user_data contains invalid character"
        );
        let mut plaintext = Vec::from(&b"comment1=cooking%20MCs;userdata="[..]);
        plaintext.extend_from_slice(&user_data.as_bytes());
        plaintext.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");

        plaintext = Padding::Pkcs7Padding(16).pad(&plaintext)?;

        let mut iv = vec![];
        iv.resize_with(16, || self.rng.borrow_mut().gen());
        let ciphertext = self.key.encrypt_cbc(&iv, &plaintext)?;
        iv.extend(ciphertext.iter());

        Ok(iv)
    }

    pub fn get_fields_16(&self, ciphertext: &[u8]) -> Result<HashMap<String, String>> {
        self.key
            .decrypt_cbc(&ciphertext[..16], &ciphertext[16..])
            .and_then(|pt| Padding::Pkcs7Padding(16).unpad(&pt))
            .map(|pt| String::from_utf8_lossy(&pt).to_string())
            .and_then(|pt| Set2Oracle::parse_kv(&pt, ';'))
    }
}

pub struct Challenge17Oracle {
    key: AesKey,
    plaintext: String,
    pub ciphertext: Vec<u8>,
}

impl Challenge17Oracle {
    pub fn new() -> Challenge17Oracle {
        let plaintexts = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ];
        let mut rng = OsRng;
        let idx = rng.gen_range(0..plaintexts.len());
        let plaintext = base64::decode(plaintexts[idx].to_owned()).unwrap();
        let padded_plaintext = Padding::Pkcs7Padding(16).pad(&plaintext).unwrap();
        let plaintext = String::from_utf8(plaintext).unwrap();

        let key = AesKey::rand_key(128).unwrap();
        let mut iv = vec![];
        iv.resize_with(16, || OsRng.gen());
        let ciphertext = key.encrypt_cbc(&iv, &padded_plaintext).unwrap();
        iv.extend(ciphertext.iter());
        let ciphertext = iv;

        Challenge17Oracle {
            key,
            plaintext,
            ciphertext,
        }
    }

    pub fn is_valid(&self, challenge: &[u8]) -> bool {
        let tmp = self.key.decrypt_cbc(&challenge[..16], &challenge[16..]);
        // println!("TMP: {:?}", tmp);
        let tmp = tmp.and_then(|pt| Padding::Pkcs7Padding(16).unpad(&pt));
        tmp.is_ok()
    }

    pub fn assert_success(&self, challenge: &str) {
        assert_eq!(self.plaintext, challenge);
    }
}

pub struct Challenge19Oracle {
    key: AesKey,
    plaintexts: Vec<String>,
    pub ciphertexts: Vec<Vec<u8>>,
}

impl Challenge19Oracle {
    pub fn new() -> Challenge19Oracle {
        let key = AesKey::rand_key(128).unwrap();
        let plaintexts: Vec<String> = [
            "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
            "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
            "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
            "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
            "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
            "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
            "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
            "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
            "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
            "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
            "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
            "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
            "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
            "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
            "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
            "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
            "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
            "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
            "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
            "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
            "U2hlIHJvZGUgdG8gaGFycmllcnM/",
            "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
            "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
            "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
            "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
            "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
            "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
            "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
            "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
            "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
            "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
            "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
            "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
            "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
            "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
            "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
            "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
            "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        ]
        .iter()
        .map(|b| base64::decode(b).unwrap())
        .map(|b| String::from_utf8(b).unwrap())
        .collect();

        let ciphertexts = plaintexts
            .iter()
            .map(|s| s.as_bytes())
            .map(|data| key.ctr(&[], data))
            .collect();

        Challenge19Oracle {
            key,
            plaintexts,
            ciphertexts,
        }
    }
}

pub struct Challenge22Oracle {
    seed: u32,
    pub clue: u32,
}

impl Challenge22Oracle {
    pub fn new() -> Challenge22Oracle {
        let sleep1 = time::Duration::from_secs(OsRng.gen_range(40..500));
        let sleep2 = time::Duration::from_secs(OsRng.gen_range(40..500));

        thread::sleep(sleep1);
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        thread::sleep(sleep2);

        let mut rng = MT19937::new(seed);
        let clue = rng.next_u32();

        Challenge22Oracle { seed, clue }
    }

    pub fn assert_success(&self, guess: u32) {
        assert_eq!(self.seed, guess);
    }
}

pub struct Challenge25Oracle {
    key: AesKey,
    original_plaintext: Vec<u8>,
    plaintext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Challenge25Oracle {
    pub fn new(plaintext: Vec<u8>) -> Self {
        let key = AesKey::rand_key(128).unwrap();
        let ciphertext = key.ctr(&[0u8; 16], &plaintext);
        let original_plaintext = plaintext.clone();
        Self {
            key,
            original_plaintext,
            plaintext,
            ciphertext,
        }
    }

    pub fn edit(&mut self, offset: usize, new_text: &[u8]) {
        if self.plaintext.len() < offset + new_text.len() {
            let extra_needed = offset + new_text.len() - self.plaintext.len();
            self.plaintext
                .extend(std::iter::repeat(0u8).take(extra_needed));
        }

        // Yes, I could just seek in, but this is easier and I'm lazy
        self.plaintext[offset..new_text.len()].copy_from_slice(new_text);
        self.ciphertext = self.key.ctr(&[0u8; 16], &self.plaintext);
    }

    pub fn assert_success(&self, guess: &[u8]) {
        assert_eq!(self.original_plaintext, guess);
    }
}

#[cfg(test)]
mod tests {
    use super::Set2Oracle;
    use anyhow::Result;

    #[test]
    fn chall13_smoke() -> Result<()> {
        let oracle = Set2Oracle::new();
        let ct = oracle.profile_for_13("salusa@salusa.dev")?;
        assert_eq!(false, oracle.is_admin_13(&ct));
        assert_eq!("user", oracle.get_role_13(&ct)?);

        Ok(())
    }
}
