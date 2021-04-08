use lazy_static::lazy_static;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{identities::Zero, One};
use rand_core::OsRng;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
