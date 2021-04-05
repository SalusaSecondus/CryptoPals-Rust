pub trait Digest: Clone {
    fn reset(&mut self);
    fn update(&mut self, input: &[u8]);
    fn digest(&mut self) -> Vec<u8>;

    fn digest_size() -> usize;
}

#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    ml: u64,
    buffer: Vec<u8>,
}

impl Default for Sha1 {
    fn default() -> Self {
        let mut result = Sha1 {
            h: [0; 5],
            ml: 0,
            buffer: vec![],
        };
        result.reset();
        return result;
    }
}

fn to_w32(chunk: &[u8]) -> Vec<u32> {
    chunk
        .chunks_exact(4)
        .map(|word| {
            (word[0] as u32) << 24 | (word[1] as u32) << 16 | (word[2] as u32) << 8 | word[3] as u32
        })
        .collect()
}

impl Sha1 {
    const CHUNK_SIZE: usize = 64;

    pub fn from_hash(hash: &[u8], length: usize) -> Self {
        let word = to_w32(hash);
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
        let mut w = to_w32(&chunk);
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
        for chunk in merged.chunks(Sha1::CHUNK_SIZE) {
            if chunk.len() != Sha1::CHUNK_SIZE {
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
        let mut padding_needed = 56i32 - (self.buffer.len() % Sha1::CHUNK_SIZE) as i32;
        if padding_needed < 0 {
            padding_needed += Sha1::CHUNK_SIZE as i32;
        }
        self.buffer
            .extend(std::iter::repeat(0).take(padding_needed as usize));
        let mut length = [0u8; 8];
        length[0] = (self.ml >> 56) as u8 & 0xff;
        length[1] = (self.ml >> 48) as u8 & 0xff;
        length[2] = (self.ml >> 40) as u8 & 0xff;
        length[3] = (self.ml >> 32) as u8 & 0xff;
        length[4] = (self.ml >> 24) as u8 & 0xff;
        length[5] = (self.ml >> 16) as u8 & 0xff;
        length[6] = (self.ml >> 8) as u8 & 0xff;
        length[7] = self.ml as u8 & 0xff;
        self.buffer.extend_from_slice(&length);
        assert_eq!(0, self.buffer.len() % Sha1::CHUNK_SIZE);
        self.buffer
            .clone()
            .chunks_exact(Sha1::CHUNK_SIZE)
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
        return 20;
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
}

#[derive(Clone)]
pub struct MD4 {
    h: [u32; 4],
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
    const CHUNK_SIZE: usize = 64;
    const  I0:u32 = 0x67452301;      /* Initial values for MD buffer */
    const  I1:u32 = 0xefcdab89;
    const  I2:u32 = 0x98badcfe;
    const  I3:u32 = 0x10325476;

    pub fn from_hash(hash: &[u8], length: usize) -> Self {
        let word: Vec<u32> = to_w32(hash).iter().map(|w| u32::from_be(*w)).collect();
        let mut h = [0u32; 4];
        h.copy_from_slice(&word);
        Self {
            h,
            ml: length as u64,
            buffer: vec![],
        }
    }

    fn compress(&mut self, chunk: &[u8]) {
        // println!("MD4 State- {:?}", self.h);

        let fs1 = 3; /* round 1 shift amounts */
        let fs2 = 7;
        let fs3 = 11;
        let fs4 = 19;
        let gs1 = 3; /* round 2 shift amounts */
        let gs2 = 5;
        let gs3 = 9;
        let gs4 = 13;
        let hs1 = 3; /* round 3 shift amounts */
        let hs2 = 9;
        let hs3 = 11;
        let hs4 = 15;

        let X: Vec<u32> = to_w32(chunk);
        let X: Vec<u32> = X.iter().map(|w| u32::from_be(*w)).collect();
        let mut A = self.h[0];
        let mut B = self.h[1];
        let mut C = self.h[2];
        let mut D = self.h[3];

        /* Update the message digest buffer */
        Self::ff(&mut A, B, C, D, 0, fs1, &X); /* Round 1 */
        Self::ff(&mut D, A, B, C, 1, fs2, &X);
        Self::ff(&mut C, D, A, B, 2, fs3, &X);
        Self::ff(&mut B, C, D, A, 3, fs4, &X);
        Self::ff(&mut A, B, C, D, 4, fs1, &X);
        Self::ff(&mut D, A, B, C, 5, fs2, &X);
        Self::ff(&mut C, D, A, B, 6, fs3, &X);
        Self::ff(&mut B, C, D, A, 7, fs4, &X);
        Self::ff(&mut A, B, C, D, 8, fs1, &X);
        Self::ff(&mut D, A, B, C, 9, fs2, &X);
        Self::ff(&mut C, D, A, B, 10, fs3, &X);
        Self::ff(&mut B, C, D, A, 11, fs4, &X);
        Self::ff(&mut A, B, C, D, 12, fs1, &X);
        Self::ff(&mut D, A, B, C, 13, fs2, &X);
        Self::ff(&mut C, D, A, B, 14, fs3, &X);
        Self::ff(&mut B, C, D, A, 15, fs4, &X);
        Self::gg(&mut A, B, C, D, 0, gs1, &X); /* Round 2 */
        Self::gg(&mut D, A, B, C, 4, gs2, &X);
        Self::gg(&mut C, D, A, B, 8, gs3, &X);
        Self::gg(&mut B, C, D, A, 12, gs4, &X);
        Self::gg(&mut A, B, C, D, 1, gs1, &X);
        Self::gg(&mut D, A, B, C, 5, gs2, &X);
        Self::gg(&mut C, D, A, B, 9, gs3, &X);
        Self::gg(&mut B, C, D, A, 13, gs4, &X);
        Self::gg(&mut A, B, C, D, 2, gs1, &X);
        Self::gg(&mut D, A, B, C, 6, gs2, &X);
        Self::gg(&mut C, D, A, B, 10, gs3, &X);
        Self::gg(&mut B, C, D, A, 14, gs4, &X);
        Self::gg(&mut A, B, C, D, 3, gs1, &X);
        Self::gg(&mut D, A, B, C, 7, gs2, &X);
        Self::gg(&mut C, D, A, B, 11, gs3, &X);
        Self::gg(&mut B, C, D, A, 15, gs4, &X);
        Self::hh(&mut A, B, C, D, 0, hs1, &X); /* Round 3 */
        Self::hh(&mut D, A, B, C, 8, hs2, &X);
        Self::hh(&mut C, D, A, B, 4, hs3, &X);
        Self::hh(&mut B, C, D, A, 12, hs4, &X);
        Self::hh(&mut A, B, C, D, 2, hs1, &X);
        Self::hh(&mut D, A, B, C, 10, hs2, &X);
        Self::hh(&mut C, D, A, B, 6, hs3, &X);
        Self::hh(&mut B, C, D, A, 14, hs4, &X);
        Self::hh(&mut A, B, C, D, 1, hs1, &X);
        Self::hh(&mut D, A, B, C, 9, hs2, &X);
        Self::hh(&mut C, D, A, B, 5, hs3, &X);
        Self::hh(&mut B, C, D, A, 13, hs4, &X);
        Self::hh(&mut A, B, C, D, 3, hs1, &X);
        Self::hh(&mut D, A, B, C, 11, hs2, &X);
        Self::hh(&mut C, D, A, B, 7, hs3, &X);
        Self::hh(&mut B, C, D, A, 15, hs4, &X);
        self.h[0] = A.overflowing_add(self.h[0]).0;
        self.h[1] = B.overflowing_add(self.h[1]).0;
        self.h[2] = C.overflowing_add(self.h[2]).0;
        self.h[3] = D.overflowing_add(self.h[3]).0;

        // println!("MD4 State: {:?}", self.h);
    }

    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (!x & z)
    }

    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }

    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    fn rot(A: u32, s: u32) -> u32 {
        A.rotate_left(s)
    }

    fn ff(A: &mut u32, B: u32, C: u32, D: u32, i: usize, s: u32, X: &[u32]) {
        *A = Self::rot(
            A.overflowing_add(Self::f(B, C, D))
                .0
                .overflowing_add(X[i])
                .0,
            s,
        );
    }
    fn gg(A: &mut u32, B: u32, C: u32, D: u32, i: usize, s: u32, X: &[u32]) {
        *A = Self::rot(
            A.overflowing_add(Self::g(B, C, D))
                .0
                .overflowing_add(X[i])
                .0
                .overflowing_add(0o13240474631)
                .0,
            s,
        );
    }
    fn hh(A: &mut u32, B: u32, C: u32, D: u32, i: usize, s: u32, X: &[u32]) {
        *A = Self::rot(
            A.overflowing_add(Self::h(B, C, D))
                .0
                .overflowing_add(X[i])
                .0
                .overflowing_add(0o15666365641)
                .0,
            s,
        );
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
        for chunk in merged.chunks(MD4::CHUNK_SIZE) {
            if chunk.len() != MD4::CHUNK_SIZE {
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
        let mut padding_needed = 56i32 - (self.buffer.len() % MD4::CHUNK_SIZE) as i32;
        if padding_needed < 0 {
            padding_needed += MD4::CHUNK_SIZE as i32;
        }
        self.buffer
            .extend(std::iter::repeat(0).take(padding_needed as usize));
        let mut length = [0u8; 8];
        length[7] = (self.ml >> 56) as u8 & 0xff;
        length[6] = (self.ml >> 48) as u8 & 0xff;
        length[5] = (self.ml >> 40) as u8 & 0xff;
        length[4] = (self.ml >> 32) as u8 & 0xff;
        length[3] = (self.ml >> 24) as u8 & 0xff;
        length[2] = (self.ml >> 16) as u8 & 0xff;
        length[1] = (self.ml >> 8) as u8 & 0xff;
        length[0] = self.ml as u8 & 0xff;
        self.buffer.extend_from_slice(&length);
        assert_eq!(0, self.buffer.len() % MD4::CHUNK_SIZE);
        self.buffer
            .clone()
            .chunks_exact(MD4::CHUNK_SIZE)
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
        return 16;
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
                padding_needed += 64 as i32;
            }
            guess.extend(std::iter::repeat(0).take(padding_needed as usize));
            let ml = ml * 8;
            let mut length = [0u8; 8];
            length[0] = (ml >> 56) as u8 & 0xff;
            length[1] = (ml >> 48) as u8 & 0xff;
            length[2] = (ml >> 40) as u8 & 0xff;
            length[3] = (ml >> 32) as u8 & 0xff;
            length[4] = (ml >> 24) as u8 & 0xff;
            length[5] = (ml >> 16) as u8 & 0xff;
            length[6] = (ml >> 8) as u8 & 0xff;
            length[7] = ml as u8 & 0xff;
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
                padding_needed += 64 as i32;
            }
            guess.extend(std::iter::repeat(0).take(padding_needed as usize));
            let ml = ml * 8;
            let mut length = [0u8; 8];
            length[7] = (ml >> 56) as u8 & 0xff;
            length[6] = (ml >> 48) as u8 & 0xff;
            length[5] = (ml >> 40) as u8 & 0xff;
            length[4] = (ml >> 32) as u8 & 0xff;
            length[3] = (ml >> 24) as u8 & 0xff;
            length[2] = (ml >> 16) as u8 & 0xff;
            length[1] = (ml >> 8) as u8 & 0xff;
            length[0] = ml as u8 & 0xff;
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
