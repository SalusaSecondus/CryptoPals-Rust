use anyhow::Context;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::One;

use crate::math::{inv_mod, rand_prime};

lazy_static! {
    static ref E3: BigUint = 3u32.into();
}

pub trait RsaKey {
    fn modulus(&self) -> &BigUint;
    fn pub_exp(&self) -> &BigUint;
}

pub trait RsaPrivateKey: RsaKey {
    fn priv_exp(&self) -> &BigUint;
}

struct RsaKeyImpl {
    modulus: BigUint,
    pub_exp: BigUint,
    priv_exp: Option<BigUint>,
}

impl RsaKey for RsaKeyImpl {
    fn modulus(&self) -> &BigUint {
        &self.modulus
    }

    fn pub_exp(&self) -> &BigUint {
        &self.pub_exp
    }
}

impl RsaPrivateKey for RsaKeyImpl {
    fn priv_exp(&self) -> &BigUint {
        &(self.priv_exp)
            .as_ref()
            .context("Not a private key")
            .unwrap()
    }
}

pub fn gen_rsa(bit_size: u64, pub_exp: &BigUint) -> (impl RsaKey, impl RsaPrivateKey) {
    loop {
        let p = rand_prime(bit_size / 2);
        let q = rand_prime(bit_size / 2);
        let totient = (&p - BigUint::one()) * (&q - BigUint::one());
        let inverse = inv_mod(pub_exp, &totient);
        if inverse.is_err() {
            continue;
        }
        let inverse = inverse.unwrap();

        let modulus = &p * &q;
        let pub_key = RsaKeyImpl {
            modulus: modulus.clone(),
            pub_exp: pub_exp.to_owned(),
            priv_exp: None
        };
        let priv_key = RsaKeyImpl {
            modulus: modulus,
            pub_exp: pub_exp.to_owned(),
            priv_exp: Some(inverse)
        };
        return (pub_key, priv_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_smoke() {
        let sizes = [512, 1024, 2048];
        for size in sizes.iter() {
            println!("Testing size {}", size);
            for trial in 0..5 {
                println!("  Testing key: {}", trial);
                let (pub_key, priv_key) = gen_rsa(*size, &E3);
                println!("    Is valid?");

                assert_eq!(pub_key.modulus(), priv_key.modulus());
                assert!(*size - pub_key.modulus().bits() < 2);
                assert_eq!(pub_key.pub_exp(), priv_key.pub_exp());
                let tmp: &BigUint = &E3;
                assert_eq!(tmp, pub_key.pub_exp());

                let plaintext = crate::math::rand_bigint(pub_key.modulus());
                let ciphertext = crate::math::mod_exp(&plaintext, pub_key.pub_exp(), pub_key.modulus());
                let decrypted = crate::math::mod_exp(&ciphertext, priv_key.priv_exp(), priv_key.modulus());

                assert_eq!(plaintext, decrypted);
            }
        }
    }
}