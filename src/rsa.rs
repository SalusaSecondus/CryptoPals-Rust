use anyhow::{ensure, Context, Result};
use asn1::ObjectIdentifier;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::One;

use crate::padding::Padding;
use crate::{
    digest::{Digest, DigestOneShot},
    math::{inv_mod, mod_exp, rand_prime, Interval},
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

#[derive(Clone)]
pub struct RsaKeyImpl {
    pub modulus: BigUint,
    pub pub_exp: BigUint,
    pub priv_exp: Option<BigUint>,
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
    let mut p = BigUint::one();
    let mut trial = 0;
    loop {
        if trial % 10 == 0 {
            // println!("Generating first prime");
            p = rand_prime(bit_size / 2);
        }
        trial += 1;
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

pub fn rsa_public_raw<R: RsaKey + ?Sized>(key: &R, data: &BigUint) -> BigUint {
    mod_exp(data, key.pub_exp(), key.modulus())
}

pub fn rsa_private_raw<R: RsaPrivateKey + ?Sized>(key: &R, data: &BigUint) -> BigUint {
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

#[allow(non_snake_case)]
pub fn bleichenbacher<K, F>(key: &K, c: &BigUint, oracle: F) -> Result<BigUint>
where
    K: RsaKey + ?Sized,
    F: Fn(&[u8]) -> bool,
{
    // Setup
    let n = key.modulus();
    let k = (n.bits() + 7) / 8;
    let one = BigUint::one();
    let two: BigUint = 2u32.into();
    let B = &one << (8 * (k - 2));
    let two_B = &two * &B;
    let three_B = &two_B + &B;
    // println!(
    //     "n = {}, 2B = {}, 3B = {}, n / 3B = {}",
    //     n.to_str_radix(16),
    //     two_B.to_str_radix(16),
    //     three_B.to_str_radix(16),
    //     n / &three_B
    // );
    // Step 1: Blinding
    println!("Bleichenbacher step 1");
    let mut s = BigUint::one();
    let mut M = vec![Interval(two_B.clone(), &three_B - &one)];
    let mut i = 1;
    // loop {
    //     let s_e = rsa_public_raw(key, &s);
    //     let c0 = (c * &s_e) % n;

    //     if oracle(&c0.to_bytes_be()) {
    //         break;
    //     }

    //     s += &one;
    // }
    let s_0 = s.clone();

    while M.len() != 1 || !M.first().context("No more intervals?!")?.width().is_one() {
        // println!("S = {}", s);
        Interval::print_stats(&M);
        // Step 2
        if i == 1 {
            println!("Bleichenbacher step 2.a");
            s = n / &three_B;
            // println!("Starting value for si = {}", s);
            // println!("c = {}", c);
            loop {
                let s_e = rsa_public_raw(key, &s);
                let c1 = (c * &s_e) % n;

                if oracle(&c1.to_bytes_be()) {
                    break;
                }
                s += &one;
                
            }
        } else if !M.len().is_one() {
            println!("Bleichenbacher step 2.b");
            loop {
                s += &one;
                let s_e = rsa_public_raw(key, &s);
                let c1 = (c * &s_e) % n;

                if oracle(&c1.to_bytes_be()) {
                    break;
                }
            }
            // todo!("Not yet implemented");
        } else {
            println!("Bleichenbacher step 2.c");
            let m = M.first().unwrap();
            let (a, b) = (&m.0, &m.1);
            let top = (b * &s) - &two_B;
            // println!("Top: {}", top);
            let mut r = &two * (top / n);
            let mut rn = &r * n;
            'two_c_loop: loop {
                // println!("r: {}", r);
                let start = (&two_B + &rn) / b;
                let end = (&three_B + &rn) / a;
                s = start;
                let mut s_e = rsa_public_raw(key, &s);
                while &s <= &end {
                    // println!("s = {}", s);
                    let c_n = (c * &s_e) % n;
                    if oracle(&c_n.to_bytes_be()) {
                        // println!("Found!");
                        break 'two_c_loop;
                    }

                    s += &one;
                    s_e = rsa_public_raw(key, &s); //(s_e * &s) % n;
                }
                r += &one;
                rn += n;
            } // two_c_loop
        }
        println!("Bleichenbacher step 3");
        // println!("s = {}", s);
        let s_minus_1 = &s - &one;
        // Step 3
        M = M
            .iter()
            .flat_map(|m| {
                let mut working = vec![];
                // println!("Interval: {}", m);
                let (a, b) = (&m.0, &m.1);
                // println!("Foo");
                // println!("as ? 3B = {} ? {}", a * &s, &three_B);
                let start = ((a * &s) - &three_B + &one) / n;
                // println!("a = {}, si = {}", a, s);

                // println!("Bar");
                let end = ((b * &s) - &two_B) / n;
                let mut r = start;
                while &r <= &end {
                    let rn = &r * n;
                    // println!("r: {}, rn: {}", r, rn);
                    let lower_candidate = (&two_B + &rn + &s_minus_1) / &s;
                    let upper_candidate = (&three_B - &one + &rn) / &s;
                    let new_lower = a.max(&lower_candidate).clone();
                    let new_upper = b.min(&upper_candidate).clone();
                    if new_lower <= new_upper {
                        working.push(Interval(new_lower, new_upper));
                    }
                    r += &one;
                }
                working
            })
            .collect();
        // println!("{:?}", M);
        // Simplify intervals
        // println!("Baz");
        let old_len = M.len();
        if old_len != 1 {
            M = Interval::simplify(M);
        }
        println!("Simplified from {} intervals to {}", old_len, M.len());
        // Step 4 increment
        i += 1;
    }
    // Step 4 Completion
    println!("Bleichenbacher step 4 (complete)");
    let result = &M.first().context("No intervals?!")?.0;
    if s_0.is_one() {
        Ok(result.clone())
    } else {
        let s_inv = inv_mod(&s_0, n)?;
        Ok((result * s_inv) % n)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        digest::Sha1,
        oracles::{Challenge46Oracle, Challenge47Oracle},
    };
    use anyhow::Result;
    use num_bigint::RandBigInt;
    use num_traits::Zero;
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

    #[test]
    #[ignore = "slow"]
    fn challenge_46() -> Result<()> {
        println!("Creating oracle");
        let oracle = Challenge46Oracle::new();

        let key = oracle.public_key();
        let ciphertext = oracle.ciphertext();

        let mut lower = BigUint::zero();
        let mut upper = key.modulus().to_owned();
        let mut current = BigUint::from_bytes_be(ciphertext);

        let two: BigUint = 2u32.into();
        let two_e = rsa_public_raw(key, &two);

        println!("Starting loop");
        let mut count = 0;
        while &upper > &lower {
            current = (current * &two_e) % key.modulus();
            let midpoint = (&upper + &lower + BigUint::one()) / &two;
            if oracle.oracle(&current.to_bytes_be()) {
                // println!("Odd");
                lower = midpoint;
            } else {
                // println!("Even");
                upper = midpoint;
            }
            count += 1;
            let upper_guess = upper.to_bytes_be();
            let lower_guess = lower.to_bytes_be();
            println!(
                "Guess({})\n\t{}\n\t{}",
                count,
                hex::encode(&upper_guess),
                hex::encode(&lower_guess)
            );
            let upper_guess = String::from_utf8_lossy(&upper_guess);
            let lower_guess = String::from_utf8_lossy(&lower_guess);
            println!("\t{}\n\t{}", upper_guess, &lower_guess);
        }
        // let upper_bytes = upper.to_bytes_be();
        // println!("Guess hex: {}", hex::encode(&upper_bytes));
        // let guess = String::from_utf8(upper_bytes)?;
        // oracle.assert_guess(&guess); // Don't know why but cannot get the final byte right
        Ok(())
    }

    #[test]
    pub fn challenge_47() -> Result<()> {
        let oracle = Challenge47Oracle::new(256);
        let ciphertext = oracle.ciphertext();
        let ciphertext = BigUint::from_bytes_be(ciphertext);
        let result = bleichenbacher(oracle.public_key(), &ciphertext, |c| oracle.lax(c))?;
        let plaintext = result.to_bytes_be();
        let plaintext = Padding::Pkcs1PaddingEncryption(256).unpad(&plaintext)?;
        let plaintext = String::from_utf8_lossy(&plaintext);
        println!("Plaintext? {}", plaintext);
        oracle.assert_guess(&plaintext);
        Ok(())
    }

    #[test]
    pub fn challenge_48() -> Result<()> {
        let oracle = Challenge47Oracle::new(768);
        let ciphertext = oracle.ciphertext();
        let ciphertext = BigUint::from_bytes_be(ciphertext);
        let result = bleichenbacher(oracle.public_key(), &ciphertext, |c| oracle.lax(c))?;
        let plaintext = result.to_bytes_be();
        // println!("Padded: {}", hex::encode(&plaintext));
        let plaintext = Padding::Pkcs1PaddingEncryption(768).unpad(&plaintext)?;
        let plaintext = String::from_utf8_lossy(&plaintext);
        println!("Plaintext? {}", plaintext);
        oracle.assert_guess(&plaintext);
        Ok(())
    }
}
