use std::fmt::Debug;

use anyhow::Result;
use lazy_static::lazy_static;
use num_bigint::{BigInt, RandBigInt};
use num_traits::{FromPrimitive as _, Zero};
use rand_core::OsRng;
use salusa_math::group::GroupElement;

lazy_static! {
    static ref CHALLENGE_57_J_FACTORS: Vec<(BigInt, BigInt)> = [
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
        BigInt::from_u128(*a).unwrap(),
        BigInt::from_u128(*b).unwrap()
    ))
    .collect();
}

fn dh_gen_key<GE, T>(g: &GE, order: &BigInt) -> Result<(BigInt, GE)>
where
    GE: GroupElement<T>,
    T: Eq + Debug + Clone,
{
    let x = OsRng.gen_bigint_range(&BigInt::zero(), order);
    let key = g.scalar_mult(&x);
    Ok((x, key))
}

fn dh_agree<GE, T>(pub_key: &GE, priv_key: &BigInt) -> GE
where
    GE: GroupElement<T>,
    T: Eq + Debug + Clone,
{
    pub_key.scalar_mult(priv_key)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, convert::TryInto as _};

    use anyhow::Result;
    use num_bigint::{BigInt, BigUint, RandBigInt};
    use num_traits::{FromPrimitive, Num, One, Zero};
    use rand_core::OsRng;
    use salusa_math::{
        crt, ec::{AffinePoint, EcCurve}, group::{pollard_kangaroo, Group as _, GroupElement as _, ZField, ZMultElement, ZMultGroup}, rand_bigint
    };

    use crate::{oracles::Challenge57_58Oracle, set8::dh_agree};

    use super::{dh_gen_key, CHALLENGE_57_J_FACTORS};

    #[test]
    pub fn challenge57() -> Result<()> {
        let oracle = Challenge57_58Oracle::new57();
        let p = BigInt::from_str_radix("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10)?;
        let p_minus = &p - BigInt::one();
        let _g = BigUint::from_str_radix("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143", 10)?;
        let q = BigInt::from_str_radix("236234353446506858198510045061214171961", 10)?;
        let _j = BigUint::from_str_radix("30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570", 10)?;

        let mut big_mod = BigInt::one();
        let mut crt_factors = vec![];
        let mut idx = 3;
        let group = ZMultGroup::modulus(&p);
        let p = p.to_biguint().unwrap();
        while big_mod < q {
            println!("{:?}", crt_factors);
            let r = &CHALLENGE_57_J_FACTORS[idx].0;
            let exp = (&p_minus / r).to_biguint().unwrap();
            // Find h
            let mut h = BigUint::one();
            while h.is_one() || h.is_zero() {
                h = rand_bigint(&p).modpow(&exp, &p);
                println!("{} {}", r, h);
            }
            let h = group.wrap(h.into())?;
            let expected_mac = oracle.oracle(&h);

            let mut x = BigInt::zero();
            loop {
                // println!("Trying {}", x);
                let key = oracle.agree(&h, &x);
                // println!("Guess: {:?}", key);
                let actual_mac = oracle.mac_with_key(&key);
                if actual_mac == expected_mac {
                    crt_factors.push((x.to_biguint().unwrap(), r.to_biguint().unwrap()));
                    big_mod *= r;
                    idx += 1;
                    break;
                }
                assert!(&x < r);
                x += BigInt::one();
            }
        }

        let result = crt(&crt_factors)?;
        println!("Found {}", result);
        assert!(oracle.check(&result.into()));
        Ok(())
    }

    #[test]
    fn challenge58() -> Result<()> {
        let p = BigInt::from_str_radix("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623", 10).unwrap();
        let group = ZMultGroup::modulus(&p);
        // let _q = BigUint::from_str_radix("335062023296420808191071248367701059461", 10).unwrap();
        // let _j = BigUint::from_str_radix("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702", 10).unwrap();
        let g = BigInt::from_str_radix("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357", 10).unwrap();
        let g = group.of(&g)?;
        let k = 14;
        let n: u64 = 4 * (0..k).map(|v| 2u64.pow(v.try_into().unwrap())).sum::<u64>() / k;
        let two = BigInt::from_u32(2).unwrap();
        let f = |y: &ZMultElement| {
            let exp = y.raw() % k;
            two.modpow(&exp, &p)
        };

        let b = BigInt::one() << 20;
        let y = BigInt::from_str_radix("7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119", 10).unwrap();
        let y = group.of(&y)?;
        let idx = pollard_kangaroo(&y, &BigInt::zero(), &b, &g, n as usize, f)?;
        println!("g^{} = {} =? {}", idx, g.scalar_mult(&idx), y);
        assert_eq!(g.scalar_mult(&idx), y);

        let k = 20;
        let n: u64 = 4 * (0..k).map(|v| 2u64.pow(v.try_into().unwrap())).sum::<u64>() / k;
        let two = BigInt::from_u32(2).unwrap();
        let f = |y: &ZMultElement| {
            let exp = y.raw() % k;
            two.modpow(&exp, &p)
        };

        let b = BigInt::one() << 40;
        let y = BigInt::from_str_radix("9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733", 10).unwrap();
        let y = group.of(&y)?;
        let idx = pollard_kangaroo(&y, &BigInt::zero(), &b, &g, n as usize, f)?;
        println!("g^{} = {} =? {}", idx, g.scalar_mult(&idx), y);
        assert_eq!(g.scalar_mult(&idx), y);
        Ok(())
    }

    #[test]
    fn challenge59_smoke() -> Result<()> {
        // finite field
        let p = BigInt::from_str_radix("11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623", 10).unwrap();
        let group = ZMultGroup::modulus(&p);
        let order = BigInt::from_str_radix("335062023296420808191071248367701059461", 10).unwrap();
        // let _j = BigUint::from_str_radix("34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702", 10).unwrap();
        let g = BigInt::from_str_radix("622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357", 10).unwrap();
        let g = group.of(&g)?;
        let kp1 = dh_gen_key(&g, &order)?;
        let kp2 = dh_gen_key(&g, &order)?;
        assert_ne!(kp1.0, kp2.0);
        assert_ne!(kp1.1, kp2.1);

        let ss1 = dh_agree(&kp1.1, &kp2.0);
        let ss2 = dh_agree(&kp2.1, &kp1.0);
        assert_eq!(ss1, ss2);
        assert_eq!(ss1.to_bytes(), ss2.to_bytes());

        // ECC
        let gf = ZField::modulus(&BigInt::from_str_radix("233970423115425145524320034830162017933", 10)?);
        let a = gf.wrap((-95051i32).into())?;
        let b = gf.wrap(11279326i32.into())?;
        let order = BigInt::from_str_radix("29246302889428143187362802287225875743", 10)?;
        let curve = EcCurve::new(a, b, Some(order.clone()));

        println!("{}", curve);

        let g = curve.wrap(
            AffinePoint::new(gf.wrap(182u32.into())?, gf.wrap(85518893674295321206118380980485522083u128.into())?)
        )?;

        let kp1 = dh_gen_key(&g, &order)?;
        let kp2 = dh_gen_key(&g, &order)?;
        assert_ne!(kp1.0, kp2.0);
        assert_ne!(kp1.1, kp2.1);

        let ss1 = dh_agree(&kp1.1, &kp2.0);
        let ss2 = dh_agree(&kp2.1, &kp1.0);
        assert_eq!(ss1, ss2);
        assert_eq!(ss1.to_bytes(), ss2.to_bytes());
        Ok(())
    }

    #[test]
    fn challenge59() -> Result<()> {
        let oracle = Challenge57_58Oracle::new59();
        // let curve = oracle.key.curve();

        let gf = ZField::modulus(&BigInt::from_str_radix("233970423115425145524320034830162017933", 10)?);
        let a = gf.wrap((-95051i32).into())?;
        
        let b = gf.wrap(210.into())?;
        let order = BigInt::from_str_radix("233970423115425145550826547352470124412", 10)?;
        let evil_curve1 = EcCurve::new_with_strict(a.clone(), b, Some(order), false);

        let b = gf.wrap(504.into())?;
        let order = BigInt::from_str_radix("233970423115425145544350131142039591210", 10)?;
        let evil_curve2 = EcCurve::new_with_strict(a.clone(), b, Some(order), false);

        let b = gf.wrap(727.into())?;
        let order = BigInt::from_str_radix("233970423115425145545378039958152057148", 10)?;
        let evil_curve3 = EcCurve::new_with_strict(a.clone(), b, Some(order), false);

        let evil_factors1 = [2u128, 3, 11, 23, 31, 89, 4999, 28411, 45361, 109138087, 39726369581];
        let evil_factors2 = [2u128, 5, 7, 11, 61, 12157, 34693, 11810604523200031240395593];
        let evil_factors3 = [2u128, 7, 23, 37, 67, 607, 1979, 13327, 13799, 66341313920192371];

        let mut strategy = BTreeMap::new();
        for f in evil_factors1 {
            if f < 11 {
                continue;
            }
            let bi = BigInt::from(f);
            strategy.entry(bi).or_insert(&evil_curve1);
        }
        for f in evil_factors2 {
            if f < 11 {
                continue;
            }
            let bi = BigInt::from(f);
            strategy.entry(bi).or_insert(&evil_curve2);
        }
        for f in evil_factors3 {
            if f < 11 {
                continue;
            }
            let bi = BigInt::from(f);
            strategy.entry(bi).or_insert(&evil_curve3);
        }

        let mut crt_factor_iter = strategy.iter();
        let mut big_mod = BigInt::one();
        let mut crt_factors = vec![];
        let q = oracle.key.curve().order().unwrap();
        while big_mod < *q {
            println!("{:?}", crt_factors);
            let (r, evil_curve) = crt_factor_iter.next().unwrap();
            let p = evil_curve.order().unwrap();
            // let p_minus = p - BigInt::one();
            let exp = p / r;
            // Find h
            let mut h = evil_curve.identity();
            while h.is_infinity() {
                let x = OsRng.gen_bigint_range(&BigInt::ZERO, &p);
                if let Ok(pt) = evil_curve.decompress(x, false) {
                    h = pt;
                    h = h.scalar_mult(&exp);
                }
                println!("{} {}", r, h);
            }
            // let h = group.wrap(h.into())?;
            let expected_mac = oracle.oracle(&h);

            let mut x = BigInt::zero();
            loop {
                // println!("Trying {}", x);
                let key = oracle.agree(&h, &x);
                // println!("Guess: {:?}", key);
                let actual_mac = oracle.mac_with_key(&key);
                if actual_mac == expected_mac {
                    println!("Found key = {} mod {} due to {}", x, r, evil_curve);
                    crt_factors.push((x.to_biguint().unwrap(), r.to_biguint().unwrap()));
                    big_mod *= r;
                    break;
                }
                assert!(&x < r);
                x += BigInt::one();
            }
        }

        let result = crt(&crt_factors)?;
        println!("Found {}", result);
        assert!(oracle.check(&result.into()));
        Ok(())
    }
}
