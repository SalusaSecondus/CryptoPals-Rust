use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::{FromPrimitive as _, One as _, Zero};
use anyhow::{bail, Result};

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

pub fn pollard_discrete_log<F>(y: &BigUint, a: &BigUint, b: &BigUint, g: &BigUint, m: &BigUint, n: usize, f: F) -> Result<BigUint>
    where F: Fn(&BigUint) -> BigUint {
    
    let mut xt = BigUint::zero();
    let mut yt = b.clone();
    println!("Generating first table to {}", n);
    let n_f = n as f64;
    for _i in 1..=n  {
        // println!("i = {}; yt = {}", _i, yt);
        if _i % 1000000 == 0 {
            println!("{}/{} ({})", _i, n, _i as f64 / n_f);
        }
        let fyt = f(&yt);
        xt += &fyt;
        yt *= g.modpow(&fyt, m);
        xt %= m;
        yt %= m;
    }

    let xt = xt;
    let yt = y;

    let mut xw = BigUint::zero();
    let mut yw = BigUint::zero();
    let limit = (b - a) + &xt;

    println!("Doing search");

    while xw < limit {
        println!("{} <? {}", xw, limit);
        let fyw = f(&yw);
        xw += &fyw;
        yw *= g.modpow(&fyw, m);
        xw %= m;
        yw %= m;

        if yw == *yt {
            return Ok(b + xt - xw);
        }
    }

    bail!("Too many iterations");
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto as _;

    use anyhow::Result;
    use num_bigint::BigUint;
    use num_traits::{FromPrimitive, Num, One, Zero};
    use salusa_math::{crt, rand_bigint};

    use crate::oracles::Challenge57Oracle;

    use super::{pollard_discrete_log, CHALLENGE_57_J_FACTORS};

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

    #[test]
    fn challenge58() -> Result<()> {
        let p = BigUint::from_str_radix("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623", 10).unwrap();
        let _q = BigUint::from_str_radix("335062023296420808191071248367701059461", 10).unwrap();
        let _j = BigUint::from_str_radix("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702", 10).unwrap();
        let g = BigUint::from_str_radix("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357", 10).unwrap();
        let k = 1u64 << 14;
        let n : u64 = (0..k).map(|v| 2u64.pow(v.try_into().unwrap())).sum::<u64>() / k;
        // let n = &k << 2;
        let two = BigUint::from_u32(2).unwrap();
        let f = |y: &BigUint| {
            let exp = y % k;
            two.modpow(&exp, &p)
            // two.pow((y % &k.try_into().unwrap())
        };

        let b = BigUint::one() << 20;
        let y = BigUint::from_str_radix("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119", 10).unwrap();
        let idx = pollard_discrete_log(&y, &BigUint::zero(), &b, &g, &p, n as usize, f)?;
        println!("idx = {}", idx);
        assert_eq!(g.modpow(&idx, &p), y);
        Ok(())
    }
}
