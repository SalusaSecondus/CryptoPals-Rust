use anyhow::{ensure, Context, Result};
use asn1::ObjectIdentifier;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::One;

use crate::padding::Padding;
use crate::{
    digest::{Digest, DigestOneShot},
    math::{inv_mod, mod_exp, rand_prime},
};

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
    // println!("Generating first prime");
    let p = rand_prime(bit_size / 2);
    loop {
        // println!("Generating second prime");
        let q = rand_prime(bit_size / 2);
        let totient = (&p - BigUint::one()) * (&q - BigUint::one());

        let inverse = inv_mod(pub_exp, &totient);
        if inverse.is_err() {
            // println!("Retrying due to bad inverse: {:?}", inverse);
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

pub fn rsa_pkcs1_15_sign<H, K>(key: &K, data: &[u8]) -> Result<Vec<u8>>
where
    K: RsaPrivateKey,
    H: Digest + DigestOneShot,
{
    let keylength = key.modulus().bits();

    let asn1_struct = rsa_pkcs1_15_generate_asn1_struct::<H>(data)?;
    let padded = Padding::Pkcs1PaddingSigning(keylength).pad(&asn1_struct)?;
    let signed = rsa_private_raw(key, &BigUint::from_bytes_be(&padded));
    Ok(signed.to_bytes_be())
}

fn rsa_pkcs1_15_generate_asn1_struct<H>(data: &[u8]) -> Result<Vec<u8>>
where
    H: Digest + DigestOneShot,
{
    let oid = H::oid().context("No OID registered")?;
    let digest = H::oneshot_digest(&data);

    Ok(asn1::write(|w| {
        //    DigestInfo ::= SEQUENCE {
        //      digestAlgorithm DigestAlgorithmIdentifier,
        //      digest Digest }
        w.write_element_with_type::<asn1::Sequence>(&|w| {
            // AlgorithmIdentifier
            // DigestAlgorithmIdentifier ::= AlgorithmIdentifier
            // AlgorithmIdentifier ::= SEQUENCE {
            //   OID
            //   NULL
            // }
            w.write_element_with_type::<asn1::Sequence>(&|w| {
                w.write_element_with_type::<ObjectIdentifier>(oid.to_owned());
                w.write_element_with_type::<()>(());
            });
            w.write_element_with_type::<&[u8]>(&digest);
        });
    }))
}

fn trim_leading_zeros(data: &[u8]) -> &[u8] {
    let mut idx = 0;
    while data[idx] == 0 {
        idx += 1;
    }
    &data[idx..]
}

pub fn rsa_pkcs1_15_verify<H, K>(key: &K, data: &[u8], signature: &[u8], strict: bool) -> Result<()>
where
    K: RsaKey,
    H: Digest + DigestOneShot,
{
    let expected_struct = rsa_pkcs1_15_generate_asn1_struct::<H>(data)?;
    let keylength = key.modulus().bits();
    let actual_padded = rsa_public_raw(key, &BigUint::from_bytes_be(signature)).to_bytes_be();
    let actual_struct = Padding::Pkcs1PaddingSigning(keylength).unpad(&actual_padded)?;
    let actual_struct = trim_leading_zeros(&actual_struct);
    // Generate rather than parse
    if strict {
        ensure!(&expected_struct == actual_struct, "Invalid signature");
    } else {
        // This section is horribly stupid, but it is annoying to incorrectly pass ASN.1 and leave a suffix,
        // so I fake it by just comparing the prefixes.

        ensure!(
            actual_struct.len() >= expected_struct.len(),
            "Structure too short"
        );
        let prefix = &actual_struct[..expected_struct.len()];
        println!("Expected: {}", hex::encode(&expected_struct));
        println!("Actual:   {}", hex::encode(&actual_struct));
        ensure!(expected_struct == prefix, "Invalid signature");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::digest::Sha1;
    use anyhow::Result;
    use num_bigint::RandBigInt;
    use rand::RngCore;
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

    #[test]
    fn challenge_41() -> Result<()> {
        let (pub_key, priv_key) = gen_rsa(512, &E3);
        println!("Modulus: {}", pub_key.modulus());
        let target_plaintext = OsRng.gen_biguint(300);

        let victim_ciphertext = rsa_public_raw(&pub_key, &target_plaintext);

        let s: BigUint = 2u32.into();
        let s_e = mod_exp(&s, pub_key.pub_exp(), pub_key.modulus());
        let s_inv = inv_mod(&s, pub_key.modulus())?;

        let tampered = (&victim_ciphertext * &s_e) % pub_key.modulus();

        // Oracle call
        let tampered_plaintext = rsa_private_raw(&priv_key, &tampered);
        // End oracle

        let decrypted = (&tampered_plaintext * s_inv) % pub_key.modulus();

        assert_eq!(target_plaintext, decrypted);

        Ok(())
    }

    #[test]
    fn rsa_sig_smoke() -> Result<()> {
        let mut msg = [0u8; 32];
        OsRng.fill_bytes(&mut msg);
        let msg = msg;

        let (pub_key, priv_key) = gen_rsa(1024, &E3);
        let signature = rsa_pkcs1_15_sign::<Sha1, _>(&priv_key, &msg)?;
        assert!(rsa_pkcs1_15_verify::<Sha1, _>(&pub_key, &msg, &signature, true).is_ok());
        assert!(rsa_pkcs1_15_verify::<Sha1, _>(&pub_key, &msg, &signature, false).is_ok());

        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 0x14;
        assert!(rsa_pkcs1_15_verify::<Sha1, _>(&pub_key, &bad_msg, &signature, true).is_err());
        assert!(rsa_pkcs1_15_verify::<Sha1, _>(&pub_key, &bad_msg, &signature, false).is_err());

        let padded = rsa_public_raw(&pub_key, &BigUint::from_bytes_be(&signature)).to_bytes_be();
        // println!("Padded: {}", hex::encode(&padded));
        let unpadded = Padding::Pkcs1PaddingSigning(pub_key.modulus().bits()).unpad(&padded)?;
        // println!("Raw signature: {}", hex::encode(&unpadded));

        let mut extended_signature = unpadded.clone();
        extended_signature.resize(extended_signature.len() + 2, 0);
        let padded = Padding::Pkcs1PaddingSigning(pub_key.modulus().bits())
            .pad(&extended_signature)
            .unwrap();
        // println!("Padded: {}", hex::encode(&padded));
        let signature = rsa_private_raw(&priv_key, &BigUint::from_bytes_be(&padded)).to_bytes_be();
        assert!(rsa_pkcs1_15_verify::<Sha1, _>(&pub_key, &msg, &signature, true).is_err());
        rsa_pkcs1_15_verify::<Sha1, _>(&pub_key, &msg, &signature, false)
    }

    #[test]
    fn challenge_42() -> Result<()> {
        let mut msg = [0u8; 32];
        OsRng.fill_bytes(&mut msg);
        let msg = msg;

        println!("Generating key");
        let (pub_key, _) = gen_rsa(2048, &E3);
        let mut asn1_struct = rsa_pkcs1_15_generate_asn1_struct::<Sha1>(&msg)?;
        let new_len = (2048 / 8) - 12;
        asn1_struct.resize(new_len, 0xff);
        let unpadded = Padding::Pkcs1PaddingSigning(pub_key.modulus().bits()).pad(&asn1_struct)?;
        println!("Calculating root");
        let root: BigUint = BigUint::from_bytes_be(&unpadded).nth_root(3);
        let signature = root.to_bytes_be();
        println!("Verifying");
        assert!(rsa_pkcs1_15_verify::<Sha1, _>(&pub_key, &msg, &signature, true).is_err());
        rsa_pkcs1_15_verify::<Sha1, _>(&pub_key, &msg, &signature, false)
    }
}
