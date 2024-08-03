use std::{collections::HashMap, fmt::{Debug, Display}, sync::mpsc::channel};

use anyhow::Result;
use lazy_static::lazy_static;
use num_bigint::{BigInt, RandBigInt};
use num_traits::{FromPrimitive as _, Zero};
use rand_core::OsRng;
use salusa_math::group::{kangaroo_search, GroupElement};
use workerpool::{thunk::{Thunk, ThunkWorker}, Pool};

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
    use std::{collections::BTreeMap, convert::TryInto as _, str::FromStr};

    use anyhow::{bail, Result};
    use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
    use num_traits::{FromPrimitive, Num, One, Zero};
    use rand_core::OsRng;
    use salusa_math::{
        crt,
        ec::{
            montgomery::{self, CRYPTO_PALS_MONTGOMERY, CRYPTO_PALS_MONTGOMERY_G},
            weierstrass::{
                self, AffinePoint, EcCurve, CRYPTO_PALS_WEIERSTRASS, CRYPTO_PALS_WEIERSTRASS_G,
            },
        },
        group::{
            kangaroo_search, kangaroo_table, pollard_kangaroo, Field, GenericFieldElement, Group as _, GroupElement, ZAddElement, ZField, ZMultElement, ZMultGroup
        },
        rand_bigint,
    };

    use crate::{oracles::Set80Oracle, set8::dh_agree};

    use super::{dh_gen_key, CHALLENGE_57_J_FACTORS};

    #[test]
    pub fn challenge57() -> Result<()> {
        let oracle = Set80Oracle::new57();
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
        let idx = pollard_kangaroo(&y, &BigInt::zero(), &b, &g, n as usize, &f)?;
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
        let idx = pollard_kangaroo(&y, &BigInt::zero(), &b, &g, n as usize, &f)?;
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
        let gf = ZField::modulus(&BigInt::from_str_radix(
            "233970423115425145524320034830162017933",
            10,
        )?);
        let a = gf.wrap((-95051i32).into())?;
        let b = gf.wrap(11279326i32.into())?;
        let order = BigInt::from_str_radix("29246302889428143187362802287225875743", 10)?;
        let curve = EcCurve::new(a, b, Some(order.clone()));

        println!("{}", curve);

        let g = curve.wrap(AffinePoint::new(
            gf.wrap(182u32.into())?,
            gf.wrap(85518893674295321206118380980485522083u128.into())?,
        ))?;

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
        let oracle = Set80Oracle::new59();
        // let curve = oracle.key.curve();

        let gf = ZField::modulus(&BigInt::from_str_radix(
            "233970423115425145524320034830162017933",
            10,
        )?);
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

        let evil_factors1 = [
            2u128,
            3,
            11,
            23,
            31,
            89,
            4999,
            28411,
            45361,
            109138087,
            39726369581,
        ];
        let evil_factors2 = [
            2u128,
            5,
            7,
            11,
            61,
            12157,
            34693,
            11810604523200031240395593,
        ];
        let evil_factors3 = [
            2u128,
            7,
            23,
            37,
            67,
            607,
            1979,
            13327,
            13799,
            66341313920192371,
        ];

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
                let x = h.curve().field().wrap(x)?;
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

    #[test]
    fn challenge60_smoke() -> Result<()> {
        let field = CRYPTO_PALS_MONTGOMERY.field();
        let mut unstrict_curve = CRYPTO_PALS_MONTGOMERY.clone();
        unstrict_curve.strict = false;

        let bad_u = field.wrap(BigInt::from_str("76600469441198017145391791613091732004")?)?;
        let bad_point = unstrict_curve.wrap(bad_u.clone())?;
        assert!(!unstrict_curve.contains(&bad_point.raw()));
        println!("{:?}", unstrict_curve.recover_v(&bad_u, true));

        let bad_11 = bad_point.scalar_mult(&11.into());
        println!("bad_11 = {}", bad_11);
        Ok(())
    }

    #[test]
    fn challenge60() -> Result<()> {
        let twist_order = BigInt::from_str("233970423115425145549737651362517029924")?;
        let twist_factors: Vec<BigInt> = [11i128, 107, 197, 1621, 105143, 405373, 2323367]
            .iter()
            .copied()
            .flat_map(BigInt::from_i128)
            .collect();
        let twist_modulus: BigInt = twist_factors.iter().product();

        let oracle = Set80Oracle::new60();
        let good_curve = oracle.key.curve();
        let field = good_curve.field();
        let key_w_x = field.wrap(oracle.key.u().raw() + BigInt::from(178))?;
        let key_w = CRYPTO_PALS_WEIERSTRASS.decompress(key_w_x, true)?;
        assert_eq!(&get_u(&key_w), oracle.key.u().raw());

        {
            let cheat = oracle.peek();
            let cheat_n = cheat / &twist_modulus;
            let cheat_r = cheat % &twist_modulus;
            assert_eq!(*cheat, &cheat_n * &twist_modulus + &cheat_r);
            let expected = CRYPTO_PALS_MONTGOMERY_G.scalar_mult(cheat);
            assert_eq!(oracle.key, expected);

            assert_eq!(&get_u(&key_w), expected.u().raw());

            let expected_w = CRYPTO_PALS_WEIERSTRASS_G.scalar_mult(&cheat);
            assert_eq!(key_w.x(), expected_w.x());

            let rg_w = CRYPTO_PALS_WEIERSTRASS_G.scalar_mult(&cheat_r);
            // let mg_w = CRYPTO_PALS_WEIERSTRASS_G.scalar_mult(&twist_modulus);

            let expected_w =
                CRYPTO_PALS_WEIERSTRASS_G.scalar_mult(&(&cheat_n * &twist_modulus)) + &rg_w;
            assert_eq!(key_w.x(), expected_w.x());

            let key_minus_remainder = &key_w - &rg_w;
            assert_eq!(
                key_minus_remainder.x(),
                CRYPTO_PALS_WEIERSTRASS_G.scalar_mult(&(&cheat_n * &twist_modulus)).x()
            );
            assert_eq!(
                key_minus_remainder,
                CRYPTO_PALS_WEIERSTRASS_G
                    .scalar_mult(&twist_modulus)
                    .scalar_mult(&cheat_n)
            );
            println!(
                "Proved theory with remainder = {} and n = {} with n * modulus = {}",
                cheat_r,
                cheat_n,
                &cheat_n * &twist_modulus
            );
            println!("log2(n) ~= {}", cheat_n.bits());
        }

        let mut crt_factors = vec![];
        // let q = oracle.key.curve().order().unwrap();
        let one = BigInt::one();
        for r in &twist_factors {
            println!("{:?}", crt_factors);
            let exp = &twist_order / r;

            // Find h
            let mut h = good_curve.identity();
            while h.is_infinity() {
                let x = OsRng.gen_bigint_range(&BigInt::ZERO, &twist_order);
                let x = field.wrap(x)?;
                if !good_curve.contains(&x) {
                    h = good_curve.wrap(x)?;
                    h = h.scalar_mult(&exp);
                }
                println!("{} {}", r, h);
            }
            // let h = group.wrap(h.into())?;
            let expected_mac = oracle.oracle(&h);

            let mut x = BigInt::zero();
            loop {
                if let Some(tmp) = x.trailing_zeros() {
                    if tmp > 20 {
                        println!("Trying {}", x);
                    }
                }
                let key = oracle.agree(&h, &x);
                // println!("Guess: {:?}", key);
                let actual_mac = oracle.mac_with_key(&key);
                if actual_mac == expected_mac {
                    println!("Found key = {} mod {}", x, r);
                    crt_factors.push((x.to_biguint().unwrap(), r.to_biguint().unwrap()));
                    break;
                }
                assert!(&x < r);
                x += &one;
            }
        }

        // Figure out all possible CRT values, then we'll weed them out.
        let x_factors = xproduct(&crt_factors);
        println!("x_factors: {:?}", x_factors);
        let r_candidates: Vec<BigInt> = x_factors
            .iter()
            .flat_map(|fs| crt(fs))
            .flat_map(|n| n.to_bigint())
            .collect();
        println!("r_candidates: {:?}", r_candidates);

        let mut actual_rs = vec![];
        {
            let exp = &twist_order / &twist_modulus;

            // Find h
            let mut h = good_curve.identity();
            while h.is_infinity() {
                let x = OsRng.gen_bigint_range(&BigInt::ZERO, &twist_order);
                let x = field.wrap(x)?;
                if !good_curve.contains(&x) {
                    h = good_curve.wrap(x)?;
                    h = h.scalar_mult(&exp);
                }
                println!("{} {}", &twist_modulus, h);
            }
            // let h = group.wrap(h.into())?;
            let expected_mac = oracle.oracle(&h);

            for x in &r_candidates {
                let key = oracle.agree(&h, &x);
                let actual_mac = oracle.mac_with_key(&key);
                if actual_mac == expected_mac {
                    println!("Found key = {} mod {}", x, twist_modulus);
                    actual_rs.push(x.clone());
                }
            }
        }
        println!("Actual rs: {:?}", actual_rs);

        let k = 22;
        let n: u64 = 4 * (0..k).map(|v| 2u64.pow(v.try_into().unwrap())).sum::<u64>() / k;
        let n : usize = n.try_into()?;
        let two = BigInt::from_u32(2).unwrap();
        let f = |y: &weierstrass::EcPoint<ZField, BigInt, ZAddElement, ZMultElement>| {
            let exp = y.x().raw() % k;
            two.modpow(&exp, CRYPTO_PALS_MONTGOMERY.field().order().unwrap())
        };

        let b = BigInt::one() << 40;
        let m_g = CRYPTO_PALS_WEIERSTRASS_G.scalar_mult(&twist_modulus);
        let table = kangaroo_table(&b, &m_g, n, &f);

        for r in actual_rs {
            println!("r = {}", r);
            println!("{} = k * G", oracle.key);
            println!("{} = (n * {} + {}) * G", oracle.key, twist_modulus, r);
            println!("{} = (n * {}) * G + ({} * G)", oracle.key, twist_modulus, r);
            let rg = CRYPTO_PALS_MONTGOMERY_G.scalar_mult(&r);
            println!("{} = (n * {}) * G + {}", oracle.key, twist_modulus, rg);

            // Double check that in weierstrass it works as well
            let rg_w = CRYPTO_PALS_WEIERSTRASS_G.scalar_mult(&r);
            println!("weierstrass: {}, montgomery: {}", rg_w, rg);
            assert_eq!(&get_u(&rg_w), rg.u().raw());

            // Moving over to weierstrass form
            println!("Now in weierstrass!");
            println!("{} = (n * {}) * G + {}", key_w, twist_modulus, rg_w);

            let key_minus_remainder = &key_w - &rg_w;

            println!(
                "{} - {} = {} = n * {} * G",
                key_w, rg, key_minus_remainder, twist_modulus
            );

            // let mg_w = CRYPTO_PALS_WEIERSTRASS_G.scalar_mult(&twist_modulus);
            println!("{} = n * {}", key_minus_remainder, m_g);

            println!("Starting kangaroo");

            // let idx = pollard_kangaroo(&key_w, &BigInt::zero(), &b, &rg_w, n as usize, &f)?;
            if let Ok(idx) = kangaroo_search(&table.0, &table.1, &key_minus_remainder, &BigInt::zero(), &b, &m_g, &f) {
                println!("Found n = {}", idx);
                println!("n * modulus = {}", &idx * &twist_modulus);
                let actual_guess = &idx * &twist_modulus + r;
                println!("Actual guess = {}", actual_guess);

                let confirmation = CRYPTO_PALS_MONTGOMERY_G.scalar_mult(&actual_guess);
                println!("{} ?+ {}", oracle.key, confirmation);

                println!("Now in weierstrass!");
                let confirmation = CRYPTO_PALS_WEIERSTRASS_G.scalar_mult(&actual_guess);
                println!("{} ?+ {}", key_w, confirmation);

                if key_w.x() == confirmation.x() {
                    println!("Actually trying.");
                    assert!(oracle.check(&actual_guess));
                    return Ok(());
                }
            }
        }
        bail!("No guess found");
    }

    fn get_u<F, GE, ME>(wpt: &weierstrass::EcPoint<F, BigInt, GE, ME>) -> BigInt
    where
        GE: GroupElement<BigInt>,
        ME: GroupElement<BigInt>,
        F: Field<BigInt, GenericFieldElement<BigInt, F, GE, ME>, GE, ME>,
    {
        let offset = BigInt::from(178);
        wpt.x().raw() - offset
    }

    fn xproduct(factors: &[(BigUint, BigUint)]) -> Vec<Vec<(BigUint, BigUint)>> {
        let mut result = vec![];
        let current = &factors[0];
        if factors.len() == 1 {
            result.push(vec![current.clone()]);
            if !current.0.is_zero() {
                let mut minus = current.clone();
                minus.0 = &minus.1 - minus.0;
                result.push(vec![minus]);
            }
            return result;
        }
        let tail = xproduct(&factors[1..]);
        for t in tail {
            let mut tmp = vec![current.clone()];
            tmp.extend_from_slice(&t);
            result.push(tmp);
            let mut minus = current.clone();
            if !minus.0.is_zero() {
                minus.0 = &minus.1 - minus.0;
                let mut tmp = vec![minus];
                tmp.extend_from_slice(&t);
                result.push(tmp);
    
            }
        }

        result
    }
}
