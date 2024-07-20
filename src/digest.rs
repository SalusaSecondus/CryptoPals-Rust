use std::convert::TryInto;

use asn1::ObjectIdentifier;
use lazy_static::lazy_static;
use num_bigint::BigUint;

pub trait Digest: Clone {
    fn reset(&mut self);
    fn update(&mut self, input: &[u8]);
    fn digest(&mut self) -> Vec<u8>;
    fn digest_num(&mut self) -> BigUint {
        BigUint::from_bytes_be(&self.digest())
    }

    fn digest_size() -> usize;
    fn block_size() -> usize;
    fn oid() -> Option<&'static ObjectIdentifier<'static>>;
}

#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    ml: u64,
    buffer: Vec<u8>,
}

pub trait DigestOneShot {
    fn oneshot_digest(input: &[u8]) -> Vec<u8>;
    fn oneshot_digest_num(input: &[u8]) -> BigUint {
        BigUint::from_bytes_be(&Self::oneshot_digest(input))
    }
}

impl<T: Digest + Default> DigestOneShot for T {
    fn oneshot_digest(input: &[u8]) -> Vec<u8> {
        let mut digest = T::default();
        digest.update(input);
        digest.digest()
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        let mut result = Sha1 {
            h: [0; 5],
            ml: 0,
            buffer: vec![],
        };
        result.reset();
        result
    }
}

pub fn to_w32_be(chunk: &[u8]) -> Vec<u32> {
    chunk
        .chunks_exact(4)
        .map(|word| u32::from_be_bytes(word.try_into().unwrap()))
        .collect()
}

impl Sha1 {
    pub fn from_hash(hash: &[u8], length: usize) -> Self {
        let word = to_w32_be(hash);
        let mut h = [0u32; 5];
        h.copy_from_slice(&word);
        Self {
            h,
            ml: length as u64,
            buffer: vec![],
        }
    }

    fn compress(&mut self, chunk: &[u8]) {
        // println!("Compress: {}", hex::encode(chunk));
        let mut w = to_w32_be(chunk);
        w.resize(80, 0);
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        // Initialize hash values
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        for i in 0..80 {
            let f: u32;
            let k: u32;
            if i <= 19 {
                f = (b & c) | ((!b) & d);
                k = 0x5A827999;
            } else if i <= 39 {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if i <= 59 {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}

impl Digest for Sha1 {
    fn reset(&mut self) {
        self.h[0] = 0x67452301;
        self.h[1] = 0xEFCDAB89;
        self.h[2] = 0x98BADCFE;
        self.h[3] = 0x10325476;
        self.h[4] = 0xC3D2E1F0;
        self.ml = 0;
        self.buffer.clear();
    }

    fn update(&mut self, input: &[u8]) {
        self.ml += (input.len() as u64) * 8u64;
        let mut merged = self.buffer.clone();
        merged.extend(input);
        for chunk in merged.chunks(Self::block_size()) {
            if chunk.len() != Self::block_size() {
                self.buffer.resize(chunk.len(), 0);
                self.buffer.copy_from_slice(chunk);
                return;
            }
            self.compress(chunk);
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        // add a trailing 1
        self.buffer.extend_from_slice(&[0x80]);
        let mut padding_needed = 56i32 - (self.buffer.len() % Self::block_size()) as i32;
        if padding_needed < 0 {
            padding_needed += Self::block_size() as i32;
        }
        self.buffer
            .extend(std::iter::repeat(0).take(padding_needed as usize));
        self.buffer.extend_from_slice(&self.ml.to_be_bytes());
        assert_eq!(0, self.buffer.len() % Self::block_size());
        self.buffer
            .clone()
            .chunks_exact(Self::block_size())
            .for_each(|c| self.compress(c));

        let mut hh = vec![];
        hh.extend_from_slice(&self.h[0].to_be_bytes());
        hh.extend_from_slice(&self.h[1].to_be_bytes());
        hh.extend_from_slice(&self.h[2].to_be_bytes());
        hh.extend_from_slice(&self.h[3].to_be_bytes());
        hh.extend_from_slice(&self.h[4].to_be_bytes());
        self.reset();
        hh
    }

    fn digest_size() -> usize {
        20
    }

    fn block_size() -> usize {
        64
    }

    fn oid() -> Option<&'static ObjectIdentifier<'static>> {
        lazy_static! {
            static ref OID: ObjectIdentifier<'static> =
                ObjectIdentifier::from_string("1.3.14.3.2.26").unwrap();
        };
        Some(&OID)
    }
}

#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    ml: u64,
    buffer: Vec<u8>,
}

impl Default for Sha256 {
    fn default() -> Self {
        let mut result = Self {
            h: [0; 8],
            ml: 0,
            buffer: vec![],
        };
        result.reset();
        result
    }
}

impl Sha256 {
    fn compress(&mut self, chunk: &[u8]) {
        let mut w = to_w32_be(chunk);
        w.resize(64, 0);
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .overflowing_add(s0)
                .0
                .overflowing_add(w[i - 7])
                .0
                .overflowing_add(s1)
                .0;
        }
        let w = w;
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;

        #[allow(non_snake_case)]
        for i in 0..64 {
            let S1 = (e.rotate_right(6)) ^ (e.rotate_right(11)) ^ (e.rotate_right(25));
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .overflowing_add(S1)
                .0
                .overflowing_add(ch)
                .0
                .overflowing_add(SHA1_K[i])
                .0
                .overflowing_add(w[i])
                .0;
            let S0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = S0.overflowing_add(maj).0;

            h = g;
            g = f;
            f = e;
            e = d.overflowing_add(temp1).0;
            d = c;
            c = b;
            b = a;
            a = temp1.overflowing_add(temp2).0;
        }

        self.h[0] = self.h[0].overflowing_add(a).0;
        self.h[1] = self.h[1].overflowing_add(b).0;
        self.h[2] = self.h[2].overflowing_add(c).0;
        self.h[3] = self.h[3].overflowing_add(d).0;
        self.h[4] = self.h[4].overflowing_add(e).0;
        self.h[5] = self.h[5].overflowing_add(f).0;
        self.h[6] = self.h[6].overflowing_add(g).0;
        self.h[7] = self.h[7].overflowing_add(h).0;
    }
}

const SHA1_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Digest for Sha256 {
    fn reset(&mut self) {
        self.h[0] = 0x6a09e667;
        self.h[1] = 0xbb67ae85;
        self.h[2] = 0x3c6ef372;
        self.h[3] = 0xa54ff53a;
        self.h[4] = 0x510e527f;
        self.h[5] = 0x9b05688c;
        self.h[6] = 0x1f83d9ab;
        self.h[7] = 0x5be0cd19;
        self.ml = 0;
        self.buffer.clear();
    }

    fn update(&mut self, input: &[u8]) {
        self.ml += (input.len() as u64) * 8u64;
        let mut merged = self.buffer.clone();
        merged.extend(input);
        for chunk in merged.chunks(Self::block_size()) {
            if chunk.len() != Self::block_size() {
                self.buffer.resize(chunk.len(), 0);
                self.buffer.copy_from_slice(chunk);
                return;
            }
            self.compress(chunk);
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        // add a trailing 1
        self.buffer.extend_from_slice(&[0x80]);
        let mut padding_needed = 56i32 - (self.buffer.len() % Self::block_size()) as i32;
        if padding_needed < 0 {
            padding_needed += Self::block_size() as i32;
        }
        self.buffer
            .extend(std::iter::repeat(0).take(padding_needed as usize));
        self.buffer.extend_from_slice(&self.ml.to_be_bytes());
        assert_eq!(0, self.buffer.len() % Self::block_size());
        self.buffer
            .clone()
            .chunks_exact(Self::block_size())
            .for_each(|c| self.compress(c));

        let mut hh = vec![];
        hh.extend_from_slice(&self.h[0].to_be_bytes());
        hh.extend_from_slice(&self.h[1].to_be_bytes());
        hh.extend_from_slice(&self.h[2].to_be_bytes());
        hh.extend_from_slice(&self.h[3].to_be_bytes());
        hh.extend_from_slice(&self.h[4].to_be_bytes());
        hh.extend_from_slice(&self.h[5].to_be_bytes());
        hh.extend_from_slice(&self.h[6].to_be_bytes());
        hh.extend_from_slice(&self.h[7].to_be_bytes());

        self.reset();
        hh
    }

    fn digest_size() -> usize {
        32
    }

    fn block_size() -> usize {
        64
    }

    fn oid() -> Option<&'static ObjectIdentifier<'static>> {
        lazy_static! {
            static ref OID: ObjectIdentifier<'static> =
                ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.1").unwrap();
        };
        Some(&OID)
    }
}

#[derive(Clone)]
pub struct PrefixMac<T: Digest> {
    key: Vec<u8>,
    digest: T,
}

impl<T: Digest> PrefixMac<T> {
    pub fn new(digest: T, key: &[u8]) -> Self {
        let mut result = Self {
            key: key.to_owned(),
            digest,
        };
        result.reset();
        result
    }
}

impl<T: Digest> Digest for PrefixMac<T> {
    fn reset(&mut self) {
        self.digest.reset();
        self.digest.update(&self.key);
    }

    fn update(&mut self, input: &[u8]) {
        self.digest.update(input);
    }

    fn digest(&mut self) -> Vec<u8> {
        let result = self.digest.digest();
        self.reset();
        result
    }

    fn digest_size() -> usize {
        T::digest_size()
    }

    fn block_size() -> usize {
        T::block_size()
    }

    fn oid() -> Option<&'static ObjectIdentifier<'static>> {
        None
    }
}

#[derive(Clone)]
pub struct MD4 {
    pub h: [u32; 4],
    ml: u64,
    buffer: Vec<u8>,
}

impl Default for MD4 {
    fn default() -> Self {
        let mut result = MD4 {
            h: [0u32; 4],
            ml: 0,
            buffer: vec![],
        };
        result.reset();
        result
    }
}

#[allow(non_snake_case)]
impl MD4 {
    pub const I0: u32 = 0x67452301; /* Initial values for MD buffer */
    pub const I1: u32 = 0xefcdab89;
    pub const I2: u32 = 0x98badcfe;
    pub const I3: u32 = 0x10325476;
    pub const SHIFTS: [u32; 12] = [
        3, 7, 11, 19, 
        3, 5, 9, 13,
        3, 9, 11, 15];
    pub const WORD_ORDER: [usize; 48] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15,
        0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15,
    ];
    pub fn from_hash(hash: &[u8], length: usize) -> Self {
        let word: Vec<u32> = to_w32_be(hash).iter().map(|w| u32::from_be(*w)).collect();
        let mut h = [0u32; 4];
        h.copy_from_slice(&word);
        Self {
            h,
            ml: length as u64,
            buffer: vec![],
        }
    }

    pub fn compress_inner(state: [u32; 4], blocks: &[u32], start: usize, end: usize) -> [u32; 4] {
        let mut state = state;
        let ops = [Self::ff1, Self::gg1, Self::hh1];

        for step in start..end {
            let round = step / 16;
            let word_idx = Self::WORD_ORDER[step];
            let op = ops[round];
            op(
                &mut state,
                step,
                blocks[word_idx],
            );
        }
        state
    }
    pub fn compress(&mut self, chunk: &[u8]) {
        // println!("MD4 State- {:?}", self.h);

        let X: Vec<u32> = to_w32_be(chunk);
        let X: Vec<u32> = X.iter().map(|w| u32::from_be(*w)).collect();
        let state = Self::compress_inner(self.h, &X, 0, Self::WORD_ORDER.len());

        self.h[0] = state[0].overflowing_add(self.h[0]).0;
        self.h[1] = state[1].overflowing_add(self.h[1]).0;
        self.h[2] = state[2].overflowing_add(self.h[2]).0;
        self.h[3] = state[3].overflowing_add(self.h[3]).0;

        // println!("MD4 State: {:?}", self.h);
    }

    pub fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    pub fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    pub fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    pub fn rot(A: u32, s: u32) -> u32 {
        A.rotate_left(s)
    }

    pub fn ff1(state: &mut [u32], step: usize, x: u32) {
        let round = step / 16;
        let mut offset = step % 4;
        if offset > 0 {
            offset = 4 - offset;
        }
        let a: usize = offset;
        let b = (offset + 1) % 4;
        let c = (b + 1) % 4;
        let d = (c + 1) % 4;

        // println!("{}, {}, {}, {}", a, b, c, d);
        state[a] = Self::rot(
            state[a]
                .overflowing_add(Self::f(state[b], state[c], state[d]))
                .0
                .overflowing_add(x)
                .0,
            Self::SHIFTS[4 * round + (step % 4)],
        );
    }

    pub fn ff(A: u32, B: u32, C: u32, D: u32, i: usize, s: u32, X: &[u32]) -> u32 {
        Self::rot(
            A.overflowing_add(Self::f(B, C, D))
                .0
                .overflowing_add(X[i])
                .0,
            s,
        )
    }

    pub fn ff2word(a1: u32, a0: u32, b: u32, c: u32, d: u32, s: u32) -> u32 {
        a1.rotate_right(s)
            .overflowing_sub(Self::f(b, c, d))
            .0
            .overflowing_sub(a0)
            .0
    }
    pub fn gg1(state: &mut [u32], step: usize, x: u32) {
        let round = step / 16;

        let mut offset = step % 4;
        if offset > 0 {
            offset = 4 - offset;
        }
        let a: usize = offset;
        let b = (offset + 1) % 4;
        let c = (b + 1) % 4;
        let d = (c + 1) % 4;

        // println!("{}, {}, {}, {}", a, b, c, d);

        state[a] = Self::rot(
            state[a]
                .overflowing_add(Self::g(state[b], state[c], state[d]))
                .0
                .overflowing_add(x)
                .0
                .overflowing_add(0o13240474631)
                .0,
            Self::SHIFTS[4 * round + (step % 4)],
        );
    }
    pub fn gg(A: u32, B: u32, C: u32, D: u32, i: usize, s: u32, X: &[u32]) -> u32 {
        Self::rot(
            A.overflowing_add(Self::g(B, C, D))
                .0
                .overflowing_add(X[i])
                .0
                .overflowing_add(0o13240474631)
                .0,
            s,
        )
    }

    pub fn gg2word(a1: u32, a0: u32, b: u32, c: u32, d: u32, s: u32) -> u32 {
        assert_ne!(a1, a0);
        a1.rotate_right(s)
            .wrapping_sub(Self::g(b, c, d))
            .wrapping_sub(a0)
            .wrapping_sub(0o13240474631)
    }

    pub fn hh1(state: &mut [u32], step: usize, x: u32) {
        let round = step / 16;

        let mut offset = step % 4;
        if offset > 0 {
            offset = 4 - offset;
        }
        let a: usize = offset;
        let b = (offset + 1) % 4;
        let c = (b + 1) % 4;
        let d = (c + 1) % 4;

        // println!("{}, {}, {}, {}", a, b, c, d);

        state[a] = Self::rot(
            state[a]
                .overflowing_add(Self::h(state[b], state[c], state[d]))
                .0
                .overflowing_add(x)
                .0
                .overflowing_add(0o15666365641)
                .0,
            Self::SHIFTS[4 * round + (step % 4)],
        );
    }

    pub fn hh(A: u32, B: u32, C: u32, D: u32, i: usize, s: u32, X: &[u32]) -> u32{
        Self::rot(
            A.overflowing_add(Self::h(B, C, D))
                .0
                .overflowing_add(X[i])
                .0
                .overflowing_add(0o15666365641)
                .0,
            s,
        )
    }
}

impl Digest for MD4 {
    fn reset(&mut self) {
        self.h = [MD4::I0, MD4::I1, MD4::I2, MD4::I3];
        self.ml = 0;
        self.buffer.clear();
    }

    fn update(&mut self, input: &[u8]) {
        self.ml += (input.len() as u64) * 8u64;
        let mut merged = self.buffer.clone();
        merged.extend(input);
        for chunk in merged.chunks(Self::block_size()) {
            if chunk.len() != Self::block_size() {
                self.buffer.resize(chunk.len(), 0);
                self.buffer.copy_from_slice(chunk);
                return;
            }
            self.compress(chunk);
        }
    }

    fn digest(&mut self) -> Vec<u8> {
        // add a trailing 1
        self.buffer.extend_from_slice(&[0x80]);
        let mut padding_needed = 56i32 - (self.buffer.len() % Self::block_size()) as i32;
        if padding_needed < 0 {
            padding_needed += Self::block_size() as i32;
        }
        self.buffer
            .extend(std::iter::repeat(0).take(padding_needed as usize));
        self.buffer.extend_from_slice(&self.ml.to_le_bytes());
        assert_eq!(0, self.buffer.len() % Self::block_size());
        self.buffer
            .clone()
            .chunks_exact(Self::block_size())
            .for_each(|c| self.compress(c));

        let mut hh = vec![];
        hh.extend_from_slice(&self.h[0].to_le_bytes());
        hh.extend_from_slice(&self.h[1].to_le_bytes());
        hh.extend_from_slice(&self.h[2].to_le_bytes());
        hh.extend_from_slice(&self.h[3].to_le_bytes());
        self.reset();
        hh
    }

    fn digest_size() -> usize {
        16
    }

    fn block_size() -> usize {
        64
    }

    fn oid() -> Option<&'static ObjectIdentifier<'static>> {
        lazy_static! {
            static ref OID: ObjectIdentifier<'static> =
                ObjectIdentifier::from_string("1.2.840.113549.2.4").unwrap();
        };
        Some(&OID)
    }
}

#[derive(Clone)]
pub struct Hmac<T: Digest> {
    digest: T,
    i_key: Vec<u8>,
    o_key: Vec<u8>,
}

impl<T: Digest + Default> Hmac<T> {
    pub fn init_new(key: &[u8]) -> Self {
        let mut digest = T::default();
        let raw_key = if key.len() > T::block_size() {
            digest.update(key);
            digest.digest()
        } else {
            let mut tmp = key.to_vec();
            tmp.resize(T::block_size(), 0);
            tmp
        };
        let o_key = crate::xor(&raw_key, &[0x5c]);
        let i_key = crate::xor(&raw_key, &[0x36]);
        let mut result = Self {
            digest,
            i_key,
            o_key,
        };
        result.reset();
        result
    }
}

impl<T: Digest + Default> Digest for Hmac<T> {
    fn reset(&mut self) {
        self.digest.reset();
        self.digest.update(&self.i_key);
    }

    fn update(&mut self, input: &[u8]) {
        self.digest.update(input);
    }

    fn digest(&mut self) -> Vec<u8> {
        let tmp = self.digest.digest();
        self.digest.update(&self.o_key);
        self.digest.update(&tmp);
        let result = self.digest.digest();
        self.reset();
        result
    }

    fn digest_size() -> usize {
        T::digest_size()
    }

    fn block_size() -> usize {
        T::block_size()
    }

    fn oid() -> Option<&'static ObjectIdentifier<'static>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use crate::oracles::Challenge29Oracle;

    use super::*;
    use hex::encode as to_hex;

    #[test]
    fn sha1_kats() {
        let vectors = vec![
            ("".as_bytes(), "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            ("abc".as_bytes(), "a9993e364706816aba3e25717850c26c9cd0d89d"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(), "84983e441c3bd26ebaae4aa1f95129e5e54670f1"),
            ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(), "a49b2446a02c645bf419f995b67091253a04a259"),
        ];
        for test in &vectors {
            let mut hash = Sha1::default();
            hash.update(test.0);
            assert_eq!(test.1, to_hex(hash.digest()));
        }

        let mut hash = Sha1::default();
        for test in &vectors {
            hash.update(test.0);
            assert_eq!(test.1, to_hex(hash.digest()));
        }

        for test in &vectors {
            assert_eq!(test.1, to_hex(Sha1::oneshot_digest(test.0)));
        }
    }

    #[test]
    fn sha256_kats() {
        let vectors = vec![
            ("".as_bytes(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            ("abc".as_bytes(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_bytes(), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
            ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
            ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstuabcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(), "b584a05e1af03e9e2201550df419266f1a18993eb8999fa98bda4a140da36a66"),

        ];
        for test in &vectors {
            let mut hash = Sha256::default();
            hash.update(test.0);
            assert_eq!(test.1, to_hex(hash.digest()));
        }

        let mut hash = Sha256::default();
        for test in &vectors {
            hash.update(test.0);
            assert_eq!(test.1, to_hex(hash.digest()));
        }

        for test in &vectors {
            assert_eq!(test.1, to_hex(Sha256::oneshot_digest(test.0)));
        }
    }

    #[test]
    fn md4_kats() {
        let vectors = vec![
            ("".as_bytes(), "31d6cfe0d16ae931b73c59d7e0c089c0"),    
            ("abc".as_bytes(), "a448017aaf21d8525fc10ae87aa6729d"),
            ("abcdefghijklmnopqrstuvwxyz".as_bytes(), "d79e1c308aa5bbcdeea8ed63df412da9"),
            ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".as_bytes(), "2102d1d94bd58ebf5aa25c305bb783ad"),
        ];
        for test in &vectors {
            let mut hash = MD4::default();
            hash.update(test.0);
            assert_eq!(test.1, to_hex(hash.digest()));
        }

        let mut hash = MD4::default();
        for test in &vectors {
            hash.update(test.0);
            assert_eq!(test.1, to_hex(hash.digest()));
        }

        for test in &vectors {
            assert_eq!(test.1, to_hex(MD4::oneshot_digest(test.0)));
        }
    }

    #[test]
    fn hmac_sha1_kats() {
        let mut hmac = Hmac::<Sha1>::init_new(b"key");
        hmac.update(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
            to_hex(hmac.digest())
        );
    }

    #[test]
    fn challenge_29() {
        let oracle = Challenge29Oracle::<Sha1>::new();
        let challenge = oracle.get_challenge();
        let message = Challenge29Oracle::<Sha1>::get_signed_message();
        // assert!(oracle.is_valid(&message, &challenge)); // Sanity check

        for secret_len in 1..20 {
            let ml = message.len() + secret_len;
            let padded_len = ((ml + 63) / 64) * 64;
            let mut hash = Sha1::from_hash(&challenge, padded_len * 8);
            let mut guess = message.clone();
            guess.push(0x80);
            let mut padding_needed = 56i32 - ((ml + 1) % 64) as i32;
            if padding_needed < 0 {
                padding_needed += 64_i32;
            }
            guess.extend(std::iter::repeat(0).take(padding_needed as usize));
            let ml = ml * 8;
            let mut length = [0u8; 8];
            length[0] = (ml >> 56) as u8;
            length[1] = (ml >> 48) as u8;
            length[2] = (ml >> 40) as u8;
            length[3] = (ml >> 32) as u8;
            length[4] = (ml >> 24) as u8;
            length[5] = (ml >> 16) as u8;
            length[6] = (ml >> 8) as u8;
            length[7] = ml as u8;
            guess.extend_from_slice(&length);
            guess.extend_from_slice(b";admin=true");
            hash.update(b";admin=true");
            let tag = hash.digest();

            if oracle.is_valid(&guess, &tag) {
                return;
            }
        }
        panic!("Could not find solution");
    }

    #[test]
    fn challenge_30() {
        let oracle = Challenge29Oracle::<MD4>::new();
        let challenge = oracle.get_challenge();
        let message = Challenge29Oracle::<MD4>::get_signed_message();
        // assert!(oracle.is_valid(&message, &challenge)); // Sanity check

        for secret_len in 1..20 {
            // println!("Len: {}", secret_len);

            let ml = message.len() + secret_len;
            let padded_len = ((ml + 63) / 64) * 64;
            let mut hash = MD4::from_hash(&challenge, padded_len * 8);
            let mut guess = message.clone();
            guess.push(0x80);
            let mut padding_needed = 56i32 - ((ml + 1) % 64) as i32;
            if padding_needed < 0 {
                padding_needed += 64_i32;
            }
            guess.extend(std::iter::repeat(0).take(padding_needed as usize));
            let ml = ml * 8;
            let mut length = [0u8; 8];
            length[7] = (ml >> 56) as u8;
            length[6] = (ml >> 48) as u8;
            length[5] = (ml >> 40) as u8;
            length[4] = (ml >> 32) as u8;
            length[3] = (ml >> 24) as u8;
            length[2] = (ml >> 16) as u8;
            length[1] = (ml >> 8) as u8;
            length[0] = ml as u8;
            guess.extend_from_slice(&length);
            guess.extend_from_slice(b";admin=true");
            hash.update(b";admin=true");
            let tag = hash.digest();

            if oracle.is_valid(&guess, &tag) {
                return;
            }
        }
        panic!("Could not find solution");
    }
}
