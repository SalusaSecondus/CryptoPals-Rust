use anyhow::{bail, ensure, Result};
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::{
    digest::DigestOneShot,
    math::{inv_mod, mod_exp, rand_bigint},
    KeyPair, PrivateKey, PublicKey,
};

#[derive(Debug, Clone)]
pub struct DsaParams {
    p: BigUint,
    q: BigUint,
    g: BigUint,
}

lazy_static! {
    static ref DSA_PARAMS : DsaParams = DsaParams {
        p: BigUint::parse_bytes(b"800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16).unwrap(),
        q: BigUint::parse_bytes(b"f4f47f05794b256174bba6e9b396a7707e563c5b", 16).unwrap(),
        g: BigUint::parse_bytes(b"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16).unwrap()
    };
}

fn dsa_ephemeral(q: &BigUint) -> BigUint {
    let one = BigUint::one();
    let limit = q - &one - &one;
    rand_bigint(&limit) + &one
}

pub fn gen_dsa(params: &DsaParams) -> KeyPair<BigUint, BigUint> {
    let x = dsa_ephemeral(&params.q);
    let y = mod_exp(&params.g, &x, &params.p);
    KeyPair {
        private_key: PrivateKey(x),
        public_key: PublicKey(y),
    }
}

fn dsa_sign_explicit_k<H>(
    params: &DsaParams,
    priv_key: &BigUint,
    data: &[u8],
    k: &BigUint,
) -> Result<[BigUint; 2]>
where
    H: DigestOneShot,
{
    let g_k = mod_exp(&params.g, k, &params.p);
    let r = g_k % &params.q;
    // if r.is_zero() {
    //     bail!("Bad k");
    // }

    let h = H::oneshot_digest_num(&data);
    let h_xr = &h + (priv_key * &r);
    let k_inv = inv_mod(&k, &params.q).unwrap();
    let s = (&k_inv * &h_xr) % &params.q;

    ensure!(!s.is_zero(), "Bad s");
    Ok([r, s])
}

pub fn dsa_sign<H>(params: &DsaParams, priv_key: &PrivateKey<BigUint>, data: &[u8]) -> [BigUint; 2]
where
    H: DigestOneShot,
{
    loop {
        let k = dsa_ephemeral(&params.q);
        if let Ok(result) = dsa_sign_explicit_k::<H>(params, priv_key, data, &k) {
            return result;
        }
    }
}

pub fn dsa_verify<H>(
    params: &DsaParams,
    y: &PublicKey<BigUint>,
    data: &[u8],
    signature: &[BigUint],
) -> Result<()>
where
    H: DigestOneShot,
{
    ensure!(signature.len() == 2, "Signature is of invalid length");
    let r = &signature[0];
    let s = &signature[1];
    ensure!(r < &params.q, "r is out of range");
    ensure!(s < &params.q, "s is out of range");
    let h = H::oneshot_digest_num(data);
    let w = inv_mod(s, &params.q)?;
    let u1 = (h * &w) % &params.q;
    let u2 = (r * &w) % &params.q;
    let g_u1 = mod_exp(&params.g, &u1, &params.p);
    let y_u2 = mod_exp(y, &u2, &params.p);
    let v = ((g_u1 * y_u2) % &params.p) % &params.q;
    ensure!(&v == r, "Signature invalid");
    Ok(())
}

pub fn recover_private(
    params: &DsaParams,
    signature: &[BigUint; 2],
    digest: &[u8],
    k: &BigUint,
) -> Result<BigUint> {
    let r = &signature[0];
    let s = &signature[1];
    let h = BigUint::from_bytes_be(digest) % &params.q;
    let top = (&params.q + (s * k) - h) % &params.q;
    let r_inv = inv_mod(r, &params.q)?;
    Ok((top * r_inv) % &params.q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Sha1;
    use anyhow::Context;
    use rand::RngCore;
    use rand_core::OsRng;

    #[test]
    pub fn dsa_smoke() -> Result<()> {
        let mut msg = [0u8; 32];
        OsRng.fill_bytes(&mut msg);
        let msg = msg;

        let keypair = gen_dsa(&DSA_PARAMS);
        let public_key = keypair.public_key;
        println!("Public key = {:?}", public_key);
        let private_key = keypair.private_key;
        let signature = dsa_sign::<Sha1>(&DSA_PARAMS, &private_key, &msg);
        dsa_verify::<Sha1>(&DSA_PARAMS, &public_key, &msg, &signature)?;

        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 0x14;
        assert!(dsa_verify::<Sha1>(&DSA_PARAMS, &public_key, &bad_msg, &signature).is_err());
        Ok(())
    }

    #[test]
    pub fn challenge_43_test() -> Result<()> {
        let keypair = gen_dsa(&DSA_PARAMS);
        let public_key = keypair.public_key;
        println!("Public key = {:?}", public_key);
        let private_key = keypair.private_key;
        let msg = b"For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
";
        let digest = Sha1::oneshot_digest(msg);
        println!("digest: {}", hex::encode(&digest));
        println!(
            "digest: {}",
            BigUint::from_bytes_be(&digest).to_str_radix(16)
        );
        let sig = dsa_sign_explicit_k::<Sha1>(&DSA_PARAMS, &private_key.0, msg, &5073u32.into())?;
        // let sig = [
        //         BigUint::parse_bytes(b"548099063082341131477253921760299949438196259240", 10).unwrap(),
        //         BigUint::parse_bytes(b"857042759984254168557880549501802188789837994940", 10).unwrap(),];
        dsa_verify::<Sha1>(&DSA_PARAMS, &public_key, msg, &sig)?;
        let guessed_x = recover_private(&DSA_PARAMS, &sig, &digest, &5073u32.into())?;
        assert_eq!(&guessed_x, &private_key.0);
        println!("Guessed: {}", guessed_x.to_str_radix(16));
        println!("Actual:  {}", private_key.0.to_str_radix(16));
        println!("Actual:  {}", public_key.0.to_str_radix(16));

        for k in 5070u32..5080 {
            // if k % 1000 == 0 {
            println!("Testing k = {} < {}", k, 2u32 << 16);
            // }
            if let Ok(x) = recover_private(&DSA_PARAMS, &sig, &digest, &k.into()) {
                // if k % 1000 == 0 {
                println!("Testing k = {}, x = {}", k, x.to_str_radix(16));
                // }
                let y = mod_exp(&DSA_PARAMS.g, &x, &DSA_PARAMS.p);
                // if k % 1000 == 0 {
                println!(
                    "Testing k = {}, x = {}, y = {}",
                    k,
                    x.to_str_radix(16),
                    y.to_str_radix(16)
                );
                // }
                if &y == &public_key.0 {
                    println!("Found k = {} and x = {}", k, x.to_str_radix(10));
                    // assert_eq!("0954edd5e0afe5542a4adf012611a91912a3ec16", hex_digest);
                    return Ok(());
                }
            }
        }
        bail!("Could not find k");
    }

    #[test]
    pub fn challenge_43() -> Result<()> {
        let public_key = PublicKey(BigUint::parse_bytes(b"84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16).unwrap());
        let msg = b"For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
";
        let digest = Sha1::oneshot_digest(msg);
        println!("digest: {}", hex::encode(&digest));
        println!(
            "digest: {}",
            BigUint::from_bytes_be(&digest).to_str_radix(16)
        );
        let sig = [
            BigUint::parse_bytes(b"548099063082341131477253921760299949438196259240", 10).unwrap(),
            BigUint::parse_bytes(b"857042759984254168557880549501802188789837994940", 10).unwrap(),
        ];
        dsa_verify::<Sha1>(&DSA_PARAMS, &public_key, msg, &sig)?;

        for k in 16000u32..(2 << 16) {
            if k % 1000 == 0 {
                println!("Testing k = {} < {}", k, 2u32 << 16);
            }
            if let Ok(x) = recover_private(&DSA_PARAMS, &sig, &digest, &k.into()) {
                if k % 1000 == 0 {
                    println!("Testing k = {}, x = {}", k, x.to_str_radix(16));
                }
                let y = mod_exp(&DSA_PARAMS.g, &x, &DSA_PARAMS.p);
                if k % 1000 == 0 {
                    println!(
                        "Testing k = {}, x = {}, y = {}",
                        k,
                        x.to_str_radix(16),
                        y.to_str_radix(16)
                    );
                }
                if &y == &public_key.0 {
                    println!("Found k = {} and x = {}", k, x.to_str_radix(10));
                    let key_digest = Sha1::oneshot_digest(&x.to_str_radix(16).as_bytes());
                    let hex_digest = hex::encode(&key_digest);
                    assert_eq!("0954edd5e0afe5542a4adf012611a91912a3ec16", hex_digest);
                    return Ok(());
                }
            }
        }
        bail!("Could not find k");
    }

    #[derive(Debug)]
    struct Entry44 {
        msg: String,
        s: BigUint,
        r: BigUint,
        m: BigUint,
    }

    fn load_44_data() -> Result<Vec<Entry44>> {
        let mut lines = crate::read_file("44.txt")?;
        let mut result = vec![];
        while let Some(line) = lines.next() {
            let line = line?;
            // msg
            let msg = line
                .splitn(2, ": ")
                .last()
                .context("Missing entry")?
                .to_owned();
            // s
            let line = lines.next().context("Missing line")??;
            let s = line
                .splitn(2, ": ")
                .last()
                .context("Missing entry")?
                .to_owned();
            let s = BigUint::parse_bytes(&s.as_bytes(), 10).context("Bad number")?;
            // r
            let line = lines.next().context("Missing line")??;
            let r = line
                .splitn(2, ": ")
                .last()
                .context("Missing entry")?
                .to_owned();
            let r = BigUint::parse_bytes(&r.as_bytes(), 10).context("Bad number")?;
            // m
            let line = lines.next().context("Missing line")??;
            let m = line
                .splitn(2, ": ")
                .last()
                .context("Missing entry")?
                .to_owned();
            let m = BigUint::parse_bytes(&m.as_bytes(), 16).context("Bad number")?;
            result.push(Entry44 { msg, s, r, m });
        }

        Ok(result)
    }

    #[test]
    pub fn challenge_44() -> Result<()> {
        let entries = load_44_data()?;
        let public_key = PublicKey(BigUint::parse_bytes(b"2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16).unwrap());
        for (e1_idx, e1) in entries.iter().enumerate() {
            for e2 in entries.iter().skip(e1_idx + 1) {
                let top = (&DSA_PARAMS.q + &e1.m - &e2.m) % &DSA_PARAMS.q;
                let bottom = (&DSA_PARAMS.q + &e1.s - &e2.s) % &DSA_PARAMS.q;
                let bottom = inv_mod(&bottom, &DSA_PARAMS.q)?;
                let k = (top * bottom) % &DSA_PARAMS.q;
                let digest = Sha1::oneshot_digest(&e1.msg.as_bytes());
                if let Ok(x) =
                    recover_private(&DSA_PARAMS, &[e1.r.clone(), e1.s.clone()], &digest, &k)
                {
                    let y = mod_exp(&DSA_PARAMS.g, &x, &DSA_PARAMS.p);
                    if &y == &public_key.0 {
                        println!("msg1: = {}\nmsg2: = {}", e1.msg, e2.msg);
                        let key_digest = Sha1::oneshot_digest(&x.to_str_radix(16).as_bytes());
                        let hex_digest = hex::encode(&key_digest);
                        assert_eq!("ca8f6f7c66fa362d40760d135b763eb8527d3d52", hex_digest);
                        return Ok(());
                    }
                }
            }
        }
        bail!("Could not find match");
    }

    #[test]
    pub fn challenge_45() -> Result<()> {
        let mut msg1 = [0u8; 32];
        OsRng.fill_bytes(&mut msg1);
        let msg1 = msg1;

        let zero_params = DsaParams {
            g: BigUint::zero(),
            .. DSA_PARAMS.clone()
        };

        let key_pair = gen_dsa(&DSA_PARAMS);
        let zero_sig = dsa_sign::<Sha1>(&zero_params, &key_pair.private_key, &msg1);
        dsa_verify::<Sha1>(&zero_params, &key_pair.public_key, &msg1, &zero_sig)?;
        println!("Zero sig: {:?}", zero_sig);
        let zero_sig = [BigUint::zero(), BigUint::one()];
        dsa_verify::<Sha1>(&zero_params, &key_pair.public_key, &msg1, &zero_sig)?;
        Ok(())
    }
}
