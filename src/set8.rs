use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::FromPrimitive as _;

lazy_static! {
    static ref CHALLENGE_57_J_FACTORS: Vec<(BigUint, BigUint)> = [
        (2u128, 1u128),
        (3, 2),
        (5, 1),
        (109, 1),
        (7963, 1),
        (8539, 1),
        (20641, 1),
        (38833, 1),
        (39341, 1),
        (46337, 1),
        (51977, 1),
        (54319, 1),
        (57529, 1),
        (96142199, 1),
        (46323892554437, 1),
        (534232641372537546151, 1),
        (80913087354323463709999234471, 1)
    ]
    .iter()
    .map(|(a, b)| (
        BigUint::from_u128(*a).unwrap(),
        BigUint::from_u128(*b).unwrap()
    ))
    .collect();
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use num_bigint::{BigInt, BigUint};
    use num_traits::{Num, One, Zero};
    use salusa_math::{crt, gcd, rand_bigint};

    use crate::oracles::Challenge57Oracle;

    use super::CHALLENGE_57_J_FACTORS;

    #[test]
    pub fn challenge57() -> Result<()> {
        let oracle = Challenge57Oracle::new();
        let p = BigUint::from_str_radix("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10)?;
        let p_minus = &p - BigUint::one();
        let _g = BigUint::from_str_radix("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143", 10)?;
        let q = BigUint::from_str_radix("236234353446506858198510045061214171961", 10)?;
        let _j = BigUint::from_str_radix("30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570", 10)?;
        
        let mut big_mod = BigUint::one();
        let mut crt_factors  = vec![];
        let mut idx = 3;
        while big_mod < q {
            println!("{:?}", crt_factors);
            let r = &CHALLENGE_57_J_FACTORS[idx].0;
            let exp = &p_minus / r;
            // Find h
            let mut h = BigUint::one();
            while h.is_one() || h.is_zero() {
                h = rand_bigint(&p).modpow(&exp, &p);
                println!("{} {}", r, h);
            }
            let expected_mac = oracle.oracle(&h);

            let mut x = BigUint::zero();
            loop {
                let key = oracle.agree(&h, &x);
                let actual_mac = oracle.mac_with_key(&key);
                if actual_mac == expected_mac {
                    crt_factors.push((x, r.clone()));
                    big_mod *= r;
                    idx += 1;
                    break;
                }
                x += BigUint::one();
            }
        }

        let result = crt(&crt_factors)?;
        println!("Found {}", result);
        assert!(oracle.check(&result));
        Ok(())
    }
}
