use std::marker::PhantomData;

use anyhow::{ensure, Context, Result};
use hex::ToHex;
use lazy_static::lazy_static;
use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_traits::One;
use rand_core::OsRng;
use salusa_math::{
    ec::weierstrass::{self, EcPoint, NIST_P256, NIST_P256_G},
    group::{
        Field, FieldElement, GenericFieldElement, Group, GroupElement, ZAddElement, ZField,
        ZMultElement
    },
};

use crate::digest::{DigestOneShot, IdentityDigest, Sha256};

lazy_static! {
    pub static ref ECDSA_P256_RAW: EcdsaParams<ZField, ZAddElement, ZMultElement, IdentityDigest> =
        EcdsaParams {
            curve: NIST_P256.clone(),
            g: NIST_P256_G.clone(),
            order_field: ZField::modulus(NIST_P256.order().unwrap()),
            _h: PhantomData::default()
        };

    pub static ref ECDSA_P256_SHA256: EcdsaParams<ZField, ZAddElement, ZMultElement, Sha256> =
        EcdsaParams {
            curve: NIST_P256.clone(),
            g: NIST_P256_G.clone(),
            order_field: ZField::modulus(NIST_P256.order().unwrap()),
            _h: PhantomData::default()
        };
}

pub struct EcdsaParams<F, GE, ME, H>
where
    GE: GroupElement<BigInt>,
    ME: GroupElement<BigInt>,
    F: Field<BigInt, GenericFieldElement<BigInt, F, GE, ME>, GE, ME>,
    H: DigestOneShot,
{
    curve: weierstrass::EcCurve<F, BigInt, GE, ME>,
    g: weierstrass::EcPoint<F, BigInt, GE, ME>,
    order_field: ZField,
    _h: PhantomData<H>,
}

#[derive(Debug, Clone)]
pub struct EcdsaSig {
    r: Vec<u8>,
    s: Vec<u8>,
}

impl EcdsaSig {
    pub fn from_p1363(val: &[u8]) -> Result<EcdsaSig> {
        ensure!(val.len() % 2 == 0);
        let half = val.len() / 2;
        let parts = val.split_at(half);
        let r = parts.0.to_vec();
        let s = parts.1.to_vec();
        Ok(EcdsaSig { r, s })
    }
}

pub fn ecdsa_sign_explicit<F, GE, ME, H>(
    params: &EcdsaParams<F, GE, ME, H>,
    key: &BigInt,
    msg: &[u8],
    k: GenericFieldElement<BigInt, ZField, ZAddElement, ZMultElement>,
    k_inv: GenericFieldElement<BigInt, ZField, ZAddElement, ZMultElement>,
) -> Result<EcdsaSig>
where
    GE: GroupElement<BigInt>,
    ME: GroupElement<BigInt>,
    F: Field<BigInt, GenericFieldElement<BigInt, F, GE, ME>, GE, ME>,
    H: DigestOneShot,
{
    // Yeah, I'm not truncating the digest even if I probably should check that....
    let field = &params.order_field;
    let h_m = field.wrap(H::oneshot_digest_num(msg).to_bigint().unwrap())?;

    let k_g = k.raw() * &params.g;
    let r = field.of(k_g.x().raw())?;

    let intermediate = h_m + key * &r;
    let s = intermediate * k_inv;

    let r = r.to_bytes();
    let s = s.to_bytes();
    Ok(EcdsaSig { r, s })
}

pub fn ecdsa_sign<F, GE, ME, H>(
    params: &EcdsaParams<F, GE, ME, H>,
    key: &BigInt,
    msg: &[u8],
) -> Result<EcdsaSig>
where
    GE: GroupElement<BigInt>,
    ME: GroupElement<BigInt>,
    F: Field<BigInt, GenericFieldElement<BigInt, F, GE, ME>, GE, ME>,
    H: DigestOneShot,
{
    // Yeah, I'm not truncating the digest even if I probably should check that....
    let order = params.curve.order().context("Order is required")?;
    let field = &params.order_field;
    let mut k = field.wrap(OsRng.gen_bigint_range(&BigInt::one(), order))?;
    let k_inv;
    loop {
        if let Ok(tmp) = k.m_inv() {
            k_inv = tmp;
            break;
        }
        k = field.wrap(OsRng.gen_bigint_range(&BigInt::one(), order))?;
    }
    ecdsa_sign_explicit(params, key, msg, k, k_inv)
}

pub fn ecdsa_verify<F, GE, ME, H>(
    params: &EcdsaParams<F, GE, ME, H>,
    key: &EcPoint<F, BigInt, GE, ME>,
    msg: &[u8],
    signature: &EcdsaSig,
) -> Result<()>
where
    GE: GroupElement<BigInt>,
    ME: GroupElement<BigInt>,
    F: Field<BigInt, GenericFieldElement<BigInt, F, GE, ME>, GE, ME>,
    H: DigestOneShot,
{
    let field = &params.order_field;
    // println!("msg: {}", msg.encode_hex::<String>());
    // println!("H(msg): {}", H::oneshot_digest(msg).encode_hex::<String>());
    // Yeah, I'm not truncating the digest even if I probably should check that....
    let z = field.from_bytes(&H::oneshot_digest(msg))?;
    let r = field.from_bytes(&signature.r)?;
    let s = field.from_bytes(&signature.s)?;

    let s_inv = s.m_inv()?;
    // Yes, I allow out of range elements...
    let u1 = &z * &s_inv;
    let u2 = &r * &s_inv;

    let point_r = u1.raw() * &params.g + u2.raw() * key;
    println!("{:?} ?= {:?}", point_r.x().raw(), &r.raw());
    ensure!(point_r.x().raw() == r.raw());
    Ok(())
}

#[cfg(test)]
mod tests {
    use hex::ToHex;
    use num_traits::Num;
    use weierstrass::{AffinePoint, NIST_P256_G};

    use super::*;

    #[test]
    fn wy_kat_verify() -> Result<()> {
        let x = NIST_P256.field().wrap(BigInt::from_str_radix("2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838", 16)?)?;
        let y = NIST_P256.field().wrap(BigInt::from_str_radix("00c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e", 16)?)?;
        let public_key = NIST_P256.wrap(AffinePoint{x, y, inf: false})?;

        println!("Public Key: ({}, {})", public_key.x().raw().to_str_radix(16), public_key.y().raw().to_str_radix(16));

        let h = hex::decode("313233343030")?;


        let signature = EcdsaSig::from_p1363(&hex::decode("2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76")?)?;


        ecdsa_verify(&ECDSA_P256_SHA256, &public_key, &h, &signature)
    }

    fn bounce_sha256() -> Result<()> {
        let private_key = OsRng.gen_bigint_range(&BigInt::one(), NIST_P256.order().context("order required")?);
        let public_key = &private_key * &*NIST_P256_G;

        let h = hex::decode("313233343030")?;
        let signature = ecdsa_sign(&ECDSA_P256_SHA256, &private_key, &h)?;

        ecdsa_verify(&ECDSA_P256_SHA256, &public_key, &h, &signature)
    }

    fn bounce_raw() -> Result<()> {
        let private_key = OsRng.gen_bigint_range(&BigInt::one(), NIST_P256.order().context("order required")?);
        let public_key = &private_key * &*NIST_P256_G;

        let h = hex::decode("313233343030")?;
        let signature = ecdsa_sign(&ECDSA_P256_RAW, &private_key, &h)?;

        ecdsa_verify(&ECDSA_P256_RAW, &public_key, &h, &signature)
    }
}
