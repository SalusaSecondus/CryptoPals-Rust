use std::{
    cell::RefCell,
    collections::HashMap,
    marker::PhantomData,
    net::SocketAddr,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::{bail, ensure, Context, Result};
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::Num;
use rand::distributions::{Distribution, Uniform};
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use std::{thread, time};
use thread::sleep;
use time::{Duration, SystemTime, UNIX_EPOCH};
use tiny_http::{Request, Response, Server};

use crate::{
    aes::AesKey,
    digest::{Hmac, Sha1},
    prng::MT19937,
    rsa::{gen_rsa, rsa_private_raw, rsa_public_raw, RsaKey, RsaKeyImpl, RsaPrivateKey},
};
use crate::{
    digest::{Digest, PrefixMac},
    padding::Padding,
};

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
    raw_key: [u8; 16],
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
            raw_key,
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

    pub fn encrypt_27(&self, user_data: &str) -> Result<Vec<u8>> {
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

        let ciphertext = self.key.encrypt_cbc(&self.raw_key, &plaintext)?;

        Ok(ciphertext)
    }

    pub fn decrypt_27(&self, ciphertext: &[u8]) -> std::result::Result<String, Vec<u8>> {
        let plaintext = self
            .key
            .decrypt_cbc(&self.raw_key, ciphertext)
            .and_then(|pt| Padding::Pkcs7Padding(16).unpad(&pt));
        if plaintext.is_err() {
            return Err(vec![]);
        }
        let plaintext = plaintext.unwrap();
        if plaintext.iter().filter(|b| **b > 127u8).count() > 0 {
            Err(plaintext)
        } else {
            Ok(String::from_utf8_lossy(&plaintext).to_string())
        }
    }

    pub fn assert_27(&self, guess: &[u8]) {
        assert_eq!(&self.raw_key, guess);
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

pub struct Challenge26Oracle {
    key: AesKey,
    rng: RefCell<OsRng>,
}

impl Challenge26Oracle {
    pub fn new() -> Self {
        let mut raw_key = [0u8; 16];
        OsRng.fill_bytes(&mut raw_key);
        let key = AesKey::new(&raw_key).unwrap();

        Self {
            key,
            rng: RefCell::new(OsRng),
        }
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

    pub fn encrypt_26(&self, user_data: &str) -> Result<Vec<u8>> {
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

        let mut iv = vec![];
        iv.resize_with(16, || self.rng.borrow_mut().gen());
        let ciphertext = self.key.ctr(&iv, &plaintext);
        iv.extend(ciphertext.iter());

        Ok(iv)
    }

    pub fn get_fields_26(&self, ciphertext: &[u8]) -> Result<HashMap<String, String>> {
        let plaintext = self.key.ctr(&ciphertext[..16], &ciphertext[16..]);
        let plaintext = String::from_utf8_lossy(&plaintext);
        Self::parse_kv(&plaintext, ';')
    }
}

pub struct Challenge29Oracle<T: Digest + Default> {
    key: Vec<u8>,
    digest_type: PhantomData<T>,
}

impl<T: Digest + Default> Challenge29Oracle<T> {
    pub fn new() -> Self {
        let prefix_range = Uniform::new_inclusive(5, 10);
        let mut key = vec![];
        key.resize_with(prefix_range.sample(&mut OsRng), || OsRng.gen());
        Self {
            key,
            digest_type: PhantomData,
        }
    }

    pub fn get_signed_message() -> Vec<u8> {
        "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
            .as_bytes()
            .to_owned()
    }

    pub fn get_challenge(&self) -> Vec<u8> {
        let mut mac = PrefixMac::new(T::default(), &self.key);
        mac.update(&Self::get_signed_message());
        mac.digest()
    }

    pub fn is_valid(&self, message: &[u8], tag: &[u8]) -> bool {
        let mut mac = PrefixMac::new(T::default(), &self.key);
        mac.update(message);
        // Yes, this next line is not constant time
        mac.digest() == tag
    }
}

pub trait OracleServerHandler: 'static + Send + Clone + Fn(&Request) -> Result<String> {}

impl<T> OracleServerHandler for T where T: 'static + Send + Clone + Fn(&Request) -> Result<String> {}

pub struct OracleServer<F: OracleServerHandler> {
    running: Arc<AtomicBool>,
    server: Arc<Server>,
    handler: F,
}

impl<F: OracleServerHandler> Drop for OracleServer<F> {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn hello_response(_rq: &Request) -> Result<String> {
    Ok("Hello world!".to_owned())
}

impl<F: OracleServerHandler> OracleServer<F> {
    pub fn new(handler: F) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let server = Arc::new(server);
        let running = Arc::new(AtomicBool::from(true));
        let result = Self {
            server,
            running,
            handler,
        };
        result.start();
        result
    }

    fn start(&self) {
        for _ in 0..4 {
            let server = self.server.clone();
            let running = self.running.clone();
            let handler = self.handler.clone();

            let _ = thread::spawn(move || {
                while running.load(std::sync::atomic::Ordering::Relaxed) {
                    match server.recv_timeout(Duration::from_millis(500)) {
                        Ok(Some(rq)) => {
                            let response = match handler(&rq) {
                                Err(err) => {
                                    Response::from_string(err.to_string()).with_status_code(400)
                                }
                                Ok(s) => Response::from_string(s),
                            };
                            let _ = rq.respond(response);
                        }
                        Ok(None) => {}
                        _ => {}
                    };
                }
            });
        }
    }

    pub fn get_server_addr(&self) -> SocketAddr {
        self.server.server_addr()
    }

    pub fn get_base_url(&self) -> String {
        let address = self.get_server_addr();
        format!("http://{}:{}/", address.ip(), address.port())
    }

    pub fn stop(&mut self) {
        self.running
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

fn parse_query_params(url: &str) -> Result<HashMap<String, String>> {
    let parts: Vec<&str> = url.splitn(2, "?").collect();
    let query_part = *parts.get(1).unwrap_or(&"");

    Set2Oracle::parse_kv(query_part, '&')
}

pub fn challenge3x(millis: u64) -> OracleServer<impl OracleServerHandler> {
    let mut key = [0u8; 20];
    OsRng.fill_bytes(&mut key[..]);
    let key = key;

    let handler = move |request: &Request| {
        let params = parse_query_params(request.url());
        let params = params?;
        let file = params.get("file").context("Missing file param")?;
        let sig = params.get("signature").context("Missing signature")?;
        let sig = hex::decode(sig)?;
        let mut hmac = Hmac::<Sha1>::init_new(&key);
        hmac.update(&file.as_bytes());
        let expected_sig = hmac.digest();
        if expected_sig.len() != sig.len() {
            bail!("Bad signature");
        }
        for (a, b) in expected_sig.iter().zip(sig.iter()) {
            sleep(Duration::from_millis(millis));
            ensure!(a == b, "Bad signature")
        }
        Ok("Good Signature".to_string())
    };

    OracleServer::new(handler)
}

pub struct Challenge46Oracle {
    key: Box<dyn RsaPrivateKey>,
    public_key: Box<dyn RsaKey>,
    ciphertext: Vec<u8>,
}

impl Challenge46Oracle {
    fn plaintext() -> String {
        let bytes = base64::decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ").unwrap();
        String::from_utf8(bytes).unwrap()
    }

    pub fn new() -> Self {
        let key_pair = gen_rsa(1024, &3u32.into());
        let plaintext = Self::plaintext();
        let plaintext = plaintext.as_bytes();
        let plaintext = BigUint::from_bytes_be(plaintext);
        let ciphertext = rsa_public_raw(&key_pair.0, &plaintext).to_bytes_be();
        Self {
            key: Box::new(key_pair.1),
            public_key: Box::new(key_pair.0),
            ciphertext,
        }
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn public_key(&self) -> &dyn RsaKey {
        self.public_key.as_ref()
    }

    pub fn oracle(&self, ciphertext: &[u8]) -> bool {
        let ciphertext = BigUint::from_bytes_be(ciphertext);
        let plaintext = rsa_private_raw(self.key.as_ref(), &ciphertext);
        // println!("Num: {}", plaintext);
        plaintext.bit(0)
    }

    pub fn assert_guess(self, plaintext: &str) {
        assert_eq!(&Self::plaintext(), plaintext);
    }

    pub fn debug(&self, ciphertext: &[u8]) {
        let ciphertext = BigUint::from_bytes_be(ciphertext);
        let plaintext = rsa_private_raw(self.key.as_ref(), &ciphertext);
        let plaintext = String::from_utf8(plaintext.to_bytes_be());
        println!("Oracle debug: {:?}", plaintext);
    }
}

pub struct Challenge47Oracle {
    key: Box<dyn RsaPrivateKey>,
    public_key: Box<dyn RsaKey>,
    ciphertext: Vec<u8>,
    padding: Padding,
}

impl Challenge47Oracle {
    pub fn smoke(pub_key: &str, priv_key: &str, padded: &str) -> Self {
        let modulus = BigUint::from_str_radix(pub_key, 16).unwrap();
        let priv_exp = Some(BigUint::from_str_radix(priv_key, 16).unwrap());
        let plaintext = BigUint::from_str_radix(padded, 16).unwrap();
        let key = RsaKeyImpl {
            modulus,
            pub_exp: 3u32.into(),
            priv_exp,
        };
        let pub_key = key.clone();
        println!("padded: {}", padded);
        let ciphertext = rsa_public_raw(&pub_key, &plaintext);
        println!("ciphertext: {}", ciphertext);
        let ciphertext = ciphertext.to_bytes_be();
        let padding = Padding::Pkcs1PaddingEncryption(key.modulus().bits());
        let key = Box::new(key);
        let public_key = Box::new(pub_key);
        Self {
            key,
            public_key,
            ciphertext,
            padding,
        }
    }
    pub fn new(bit_size: u64) -> Self {
        let key_pair = gen_rsa(bit_size, &3u32.into());
        let plaintext = "kick it, CC";
        let plaintext = plaintext.as_bytes();
        let padding = Padding::Pkcs1PaddingEncryption(bit_size);
        let plaintext = padding.pad(plaintext).unwrap();
        println!("Padded: {}", hex::encode(&plaintext));
        let plaintext = BigUint::from_bytes_be(&plaintext);
        let ciphertext = rsa_public_raw(&key_pair.0, &plaintext).to_bytes_be();
        Self {
            key: Box::new(key_pair.1),
            public_key: Box::new(key_pair.0),
            padding,
            ciphertext,
        }
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn public_key(&self) -> &dyn RsaKey {
        self.public_key.as_ref()
    }

    pub fn lax(&self, ciphertext: &[u8]) -> bool {
        // println!("Calling oracle");
        let ciphertext = BigUint::from_bytes_be(ciphertext);
        let plaintext = rsa_private_raw(self.key.as_ref(), &ciphertext);
        let plaintext = plaintext.to_bytes_be();
        // println!("\t{} <- {}", hex::encode(&plaintext), ciphertext.to_str_radix(16));
        let em_len: usize = ((self.key.modulus().bits() + 7) / 8) as usize;
        let base_index = if plaintext.len() == em_len {
            if plaintext[0] != 0 {
                return false;
            }
            1
        } else if plaintext.len() == em_len - 1 {
            0
        } else {
            return false;
        };
        plaintext[base_index] == 2
    }

    pub fn strict(&self, ciphertext: &[u8]) -> bool {
        let ciphertext = BigUint::from_bytes_be(ciphertext);
        let plaintext = rsa_private_raw(self.key.as_ref(), &ciphertext);
        self.padding.unpad(&plaintext.to_bytes_be()).is_ok()
    }

    pub fn assert_guess(self, plaintext: &str) {
        assert_eq!("kick it, CC", plaintext);
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

    #[test]
    fn server() -> Result<()> {
        let server = super::OracleServer::new(super::hello_response);
        let client = reqwest::blocking::Client::new();
        let request = client.get(server.get_base_url());
        let result = request.send()?;
        assert!(result.status().is_success());
        assert_eq!("Hello world!", result.text()?);
        Ok(())
    }
}
