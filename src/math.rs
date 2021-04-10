use lazy_static::lazy_static;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{identities::Zero, One};
use rand_core::OsRng;
use rand::RngCore;

use crate::{aes::AesKey, digest::{Digest, Sha1}};

#[derive(Clone)]
pub struct FieldP {
    pub g: BigUint,
    pub p: BigUint,
}

pub fn challenge_33_params() -> &'static FieldP {
    lazy_static! {
        static ref FIELD: FieldP = FieldP{
             p: BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap(),
             g: 2u32.into()};
    }
    &FIELD
}

pub fn rand_bigint(limit: &BigUint) -> BigUint {
    OsRng.gen_biguint_range(&BigUint::zero(), limit)
}

pub fn mod_exp(base: &BigUint, exp: &BigUint, modulo: &BigUint) -> BigUint {
    // println!("mod_exp({}, {}, {})", base, exp, modulo);
    // We're not going to bother with the iterative solution and will just do the recursive (so long as it doesn't crash)
    if exp.is_zero() {
        return BigUint::one();
    } else if exp.is_one() {
        return base.clone();
    }

    let sqrt = exp >> 1;
    let result = mod_exp(base, &sqrt, &modulo);
    let result = &result * &result;
    if exp.bit(0) {
        (result * base) % modulo
    } else {
        result % modulo
    }
}

struct Challenge34Actor {
    me: BigUint,
    me_public: BigUint,
    field: FieldP,
    s: Option<AesKey>,
    msg: Option<Vec<u8>>
}

impl Challenge34Actor {
    fn new_a() -> Self {
        let field = challenge_33_params().clone();
        let me = rand_bigint(&field.p);
        let me_public = mod_exp(&field.g, &me, &field.p);
        Self {field, me, me_public, s: None, msg: None}
    }

    fn new_b(p: &BigUint, g: &BigUint, other_public: &BigUint) -> Self {
        let field = FieldP {p: p.clone(), g: g.clone()};
        let me = rand_bigint(&field.p);
        let me_public = mod_exp(&field.g, &me, &field.p);
        let s = Self::derive_key(&mod_exp(other_public, &me, &field.p));
        let s = Some(s);
        Self {field, me, me_public, s, msg: None}
    }

    fn update_other(&mut self, other_public: &BigUint) -> Vec<u8> {
        let s = Self::derive_key(&mod_exp(other_public, &self.me, &self.field.p));
        self.s = Some(s);
        let mut message = vec![0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut message);
        let mut iv = vec![0u8; 16];
        rng.fill_bytes(&mut iv);

        let ciphertext = s.encrypt_cbc(&iv, &message).unwrap();
        self.msg = Some(message);
        iv.extend(ciphertext.iter());
        iv    
    }

    fn echo(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let s = self.s.unwrap();
        let message = s.decrypt_cbc(&ciphertext[..16], &ciphertext[16..]).unwrap();

        let mut rng = OsRng;
        let mut iv = vec![0u8; 16];
        rng.fill_bytes(&mut iv);

        let ciphertext = s.encrypt_cbc(&iv, &message).unwrap();
        self.msg = Some(message);
        iv.extend(ciphertext.iter());
        iv    
    }

    fn hear_echo(&self, ciphertext: &[u8]) {
        let s = self.s.unwrap();
        let message = s.decrypt_cbc(&ciphertext[..16], &ciphertext[16..]).unwrap();
        assert_eq!(self.msg, Some(message));
    }

    fn assert_msg(&self, msg: &[u8]) {
        let foo = &self.msg;
        let bar = foo.as_deref();
        assert_eq!(bar.unwrap(), msg);
    }

    fn derive_key(s: &BigUint) -> AesKey {
        let mut hash = Sha1::default();
        hash.update(&s.to_bytes_be());
        let raw_key = &hash.digest()[..16];
        AesKey::new(raw_key).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn exp_test() {
        let base: BigUint = 3u32.into();
        let prime: BigUint = 31u32.into();
        let mut expected = BigUint::one();

        for exp in 0u32..32 {
            assert_eq!(expected, mod_exp(&base, &exp.into(), &prime));
            println!("5^{} = {} mod {}", exp, expected, prime);
            expected = (expected * &base) % &prime;
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn challenge_33() {
        let p: BigUint = 37u32.into();
        let g: BigUint = 5u32.into();

        let a = rand_bigint(&p);
        let b = rand_bigint(&p);
        assert!(a < p && a >= BigUint::zero());
        assert!(b < p && b >= BigUint::zero());
        let aA = mod_exp(&g, &a, &p);
        let bB = mod_exp(&g, &b, &p);

        let aS = mod_exp(&bB, &a, &p);
        let bS = mod_exp(&aA, &b, &p);
        println!("a = {}, A = {}", a, aA);
        println!("b = {}, bB = {}", b, bB);
        println!("S = {}", aS);
        assert_eq!(aS, bS);

        // Actual params
        let field = challenge_33_params();
        let a = rand_bigint(&field.p);
        let b = rand_bigint(&field.p);
        let aA = mod_exp(&g, &a, &field.p);
        let bB = mod_exp(&g, &b, &field.p);

        let aS = mod_exp(&bB, &a, &field.p);
        let bS = mod_exp(&aA, &b, &field.p);
        println!("a = {}, A = {}", a, aA);
        println!("b = {}, bB = {}", b, bB);
        println!("S = {}", aS);
        assert_eq!(aS, bS);
    }

    #[test]
    fn challenge_34() -> Result<()> {
        // Prove that this works
        let mut a = Challenge34Actor::new_a();
        let mut b = Challenge34Actor::new_b(&a.field.p, &a.field.g, &a.me_public);
        let ciphertext = a.update_other(&b.me_public);
        let echo = b.echo(&ciphertext);
        assert!(ciphertext != echo);
        a.hear_echo(&echo);
    
        // Actual challenge with MitM
        let mut a = Challenge34Actor::new_a();
        let (_valid_a, valid_g, valid_p) = (a.me_public.clone(), a.field.g.clone(), a.field.p.clone());
        let mut b = Challenge34Actor::new_b(&valid_p, &valid_g, &valid_p);
        let _valid_b = &b.me_public;
        let ciphertext = a.update_other(&valid_p);
        let echo = b.echo(&ciphertext);
        assert!(ciphertext != echo);
        a.hear_echo(&echo);
        // Derive key based on known values
        let key = Challenge34Actor::derive_key(&BigUint::zero());
        let message = key.decrypt_cbc(&ciphertext[..16], &ciphertext[16..])?;
        let message2 = key.decrypt_cbc(&ciphertext[..16], &ciphertext[16..])?;
        assert_eq!(message, message2);
        a.assert_msg(&message);
        b.assert_msg(&message);

        Ok(())
    }

}
