use anyhow::Context;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::One;

use crate::math::{inv_mod, mod_exp, rand_prime};

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
            priv_exp: None,
        };
        let priv_key = RsaKeyImpl {
            modulus: modulus,
            pub_exp: pub_exp.to_owned(),
            priv_exp: Some(inverse),
        };
        return (pub_key, priv_key);
    }
}

fn rsa_public_raw<R: RsaKey>(key: &R, data: &BigUint) -> BigUint {
    mod_exp(data, key.pub_exp(), key.modulus())
}

fn rsa_private_raw<R: RsaPrivateKey>(key: &R, data: &BigUint) -> BigUint {
    mod_exp(data, key.priv_exp(), key.modulus())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use num_bigint::RandBigInt;
    use rand_core::OsRng;

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
                let ciphertext = rsa_public_raw(&pub_key, &plaintext);
                let decrypted = rsa_private_raw(&priv_key, &ciphertext);

                assert_eq!(plaintext, decrypted);
            }
        }
    }

    #[test]
    fn challenge_40() -> Result<()> {
        let target_plaintext = OsRng.gen_biguint(300);

        println!("Gen key 1");
        let (pub_0, _) = gen_rsa(512, &E3);
        println!("Gen key 2");
        let (pub_1, _) = gen_rsa(512, &E3);
        println!("Gen key 3");
        let (pub_2, _) = gen_rsa(512, &E3);
        println!("Let's get cracking!");

        let c_0 = rsa_public_raw(&pub_0, &target_plaintext);
        let c_1 = rsa_public_raw(&pub_1, &target_plaintext);
        let c_2 = rsa_public_raw(&pub_2, &target_plaintext);

        // Mount actual attack
        let n_0 = pub_0.modulus();
        let n_1 = pub_1.modulus();
        let n_2 = pub_2.modulus();

        let n_012 = n_0 * n_1 * n_2;
        let m_s_0 = &n_012 / n_0;
        let m_s_1 = &n_012 / n_1;
        let m_s_2 = &n_012 / n_2;

        let result = ((&c_0 * &m_s_0 * inv_mod(&m_s_0, &n_0)?)
            + (&c_1 * &m_s_1 * inv_mod(&m_s_1, &n_1)?)
            + (&c_2 * &m_s_2 * inv_mod(&m_s_2, &n_2)?))
            % n_012;

        let result = result.nth_root(3);
        assert_eq!(target_plaintext, result);

        Ok(())
    }
}
