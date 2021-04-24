use anyhow::{bail, ensure, Result};
use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::{
    digest::DigestOneShot,
    math::{inv_mod, mod_exp, rand_bigint},
    KeyPair, PrivateKey, PublicKey,
};

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
    if r.is_zero() {
        bail!("Bad k");
    }

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
        if let Ok(result) = dsa_sign_explicit_k::<H>(params, &priv_key.0, data, &k) {
            return result;
        }
    }
}

pub fn dsa_verify<H>(
    params: &DsaParams,
    pub_key: &PublicKey<BigUint>,
    data: &[u8],
    signature: &[BigUint],
) -> Result<()>
where
    H: DigestOneShot,
{
    ensure!(signature.len() == 2, "Signature is of invalid length");
    let y = &pub_key.0;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Sha1;
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
}
