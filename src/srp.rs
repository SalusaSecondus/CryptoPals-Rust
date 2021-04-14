use std::{collections::HashMap, marker::PhantomData};

use anyhow::{Context, Result};
use lazy_static::lazy_static;
use num_bigint::BigUint;

use crate::digest::{Digest, Hmac, Sha256};
use crate::math::{mod_exp, rand_bigint};

lazy_static! {
    static ref NIST_PRIME: BigUint =  BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
    pub static ref SRP_STANDARD: SrpParams<Sha256>  = SrpParams {
        n: NIST_PRIME.clone(),
        g: 2u32.into(),
        k: 3u32.into(),
        phantom: PhantomData,
    };
}

#[derive(Clone)]
pub struct SrpParams<H: Digest + Default> {
    n: BigUint,
    g: BigUint,
    k: BigUint,
    phantom: PhantomData<H>,
}

pub struct SrpServer<H: Digest + Default> {
    params: SrpParams<H>,
    verifiers: HashMap<String, (BigUint, BigUint)>,
}

pub fn gen_srp_verifier<H>(params: &SrpParams<H>, password: &str) -> (BigUint, BigUint)
where
    H: Digest + Default,
{
    let salt = rand_bigint(&params.n);
    let mut digest = H::default();
    digest.update(&salt.to_bytes_be());
    digest.update(&password.as_bytes());
    let x_h = digest.digest();
    let x_h = BigUint::from_bytes_be(&x_h);
    let v = mod_exp(&params.g, &x_h, &params.n);
    (salt, v)
}

pub struct SrpServerState {
    pub s: BigUint,
    pub b_pub: BigUint,
    expected_response: Vec<u8>,
}

pub struct SrpClient<H>
where
    H: Digest + Default,
{
    params: SrpParams<H>,
    a: BigUint,
    a_pub: BigUint,
    key: Option<Vec<u8>>,
}

impl<H> SrpServer<H>
where
    H: Digest + Default,
{
    pub fn new(params: SrpParams<H>) -> Self {
        Self {
            params,
            verifiers: HashMap::new(),
        }
    }

    pub fn save_verifier(&mut self, email: &str, verifier: (BigUint, BigUint)) {
        self.verifiers.insert(email.to_string(), verifier);
    }

    pub fn start_login(&self, email: &str, a_pub: &BigUint) -> Result<SrpServerState> {
        let verifier = self.verifiers.get(email).context("Unknown email")?;
        let (s, v) = (verifier.0.clone(), &verifier.1);
        let b = rand_bigint(&self.params.n);
        let kv = &self.params.k * v;
        let g_b = mod_exp(&self.params.g, &b, &self.params.n);
        let b_pub = kv + g_b;
        let mut digest = H::default();
        digest.update(&a_pub.to_bytes_be());
        digest.update(&b_pub.to_bytes_be());
        let u = BigUint::from_bytes_be(&digest.digest());

        let v_u = mod_exp(v, &u, &self.params.n);
        let av_u = a_pub * v_u;
        let secret = mod_exp(&av_u, &b, &self.params.n);
        digest.update(&secret.to_bytes_be());
        let key = digest.digest();
        let mut hmac = Hmac::<H>::init_new(&key);
        hmac.update(&s.to_bytes_be());
        let expected_response = hmac.digest();
        Ok(SrpServerState {
            s,
            b_pub,
            expected_response,
        })
    }

    pub fn login(&self, state: SrpServerState, response: Vec<u8>) -> bool {
        // Yes, this should be constant time....
        response == state.expected_response
    }
}

impl<H> SrpClient<H>
where
    H: Digest + Default,
{
    pub fn new(params: SrpParams<H>) -> Self {
        let a = rand_bigint(&params.n);
        let a_pub = mod_exp(&params.g, &a, &params.n);
        Self {
            params,
            a,
            a_pub,
            key: None,
        }
    }

    pub fn get_a(&self) -> &BigUint {
        &self.a_pub
    }

    pub fn process_params(&mut self, salt: &BigUint, b_pub: &BigUint, password: &str) -> Vec<u8> {
        let salt = salt.to_bytes_be();
        let mut digest = H::default();
        digest.update(&self.a_pub.to_bytes_be());
        digest.update(&b_pub.to_bytes_be());
        let u = BigUint::from_bytes_be(&digest.digest());

        digest.update(&salt);
        digest.update(&password.as_bytes());
        let x = BigUint::from_bytes_be(&digest.digest());

        let g_x = mod_exp(&self.params.g, &x, &self.params.n);
        // Start by adding n to ensure we stay above 0
        let base = &self.params.n + b_pub - (&self.params.k * g_x);
        let exp = &self.a + (u * x);
        let key = mod_exp(&base, &exp, &self.params.n);
        digest.update(&key.to_bytes_be());
        let key = digest.digest();

        let mut hmac = Hmac::<H>::init_new(&key);
        self.key = Some(key);

        hmac.update(&salt);
        hmac.digest()
    }
}

struct SimpleSrpClient<H: Digest + Default> {
    params: SrpParams<H>,
    a: BigUint,
    a_pub: BigUint,
    key: Option<Vec<u8>>,
}

impl<H> SimpleSrpClient<H>
where
    H: Digest + Default,
{
    pub fn new(params: SrpParams<H>) -> Self {
        let a = rand_bigint(&params.n);
        let a_pub = mod_exp(&params.g, &a, &params.n);
        Self {
            params,
            a,
            a_pub,
            key: None,
        }
    }

    pub fn get_a(&self) -> &BigUint {
        &self.a_pub
    }

    pub fn process_params(&mut self, salt: &BigUint, b_pub: &BigUint, password: &str) -> Vec<u8> {
        let salt = salt.to_bytes_be();
        let mut digest = H::default();
        digest.update(&self.a_pub.to_bytes_be());
        digest.update(&b_pub.to_bytes_be());
        let u = BigUint::from_bytes_be(&digest.digest());

        digest.update(&salt);
        digest.update(&password.as_bytes());
        let x = BigUint::from_bytes_be(&digest.digest());

        // Start by adding n to ensure we stay above 0
        let exp = &self.a + (u * x);
        let key = mod_exp(&b_pub, &exp, &self.params.n);
        digest.update(&key.to_bytes_be());
        let key = digest.digest();

        let mut hmac = Hmac::<H>::init_new(&key);
        self.key = Some(key);

        hmac.update(&salt);
        hmac.digest()
    }
}

struct SimpleSrpServer<H: Digest + Default> {
    params: SrpParams<H>,
    verifiers: HashMap<String, (BigUint, BigUint)>,
}

impl<H> SimpleSrpServer<H>
where
    H: Digest + Default,
{
    pub fn new(params: SrpParams<H>) -> Self {
        Self {
            params,
            verifiers: HashMap::new(),
        }
    }

    pub fn save_verifier(&mut self, email: &str, verifier: (BigUint, BigUint)) {
        self.verifiers.insert(email.to_string(), verifier);
    }

    pub fn start_login(&self, email: &str, a_pub: &BigUint) -> Result<SrpServerState> {
        let verifier = self.verifiers.get(email).context("Unknown email")?;
        let (s, v) = (verifier.0.clone(), &verifier.1);
        let b = rand_bigint(&self.params.n);
        let b_pub = mod_exp(&self.params.g, &b, &self.params.n);
        let mut digest = H::default();
        digest.update(&a_pub.to_bytes_be());
        digest.update(&b_pub.to_bytes_be());
        let u = BigUint::from_bytes_be(&digest.digest());

        let v_u = mod_exp(v, &u, &self.params.n);
        let av_u = a_pub * v_u;
        let secret = mod_exp(&av_u, &b, &self.params.n);
        digest.update(&secret.to_bytes_be());
        let key = digest.digest();
        let mut hmac = Hmac::<H>::init_new(&key);
        hmac.update(&s.to_bytes_be());
        let expected_response = hmac.digest();
        Ok(SrpServerState {
            s,
            b_pub,
            expected_response,
        })
    }

    pub fn login(&self, state: SrpServerState, response: Vec<u8>) -> bool {
        // Yes, this should be constant time....
        response == state.expected_response
    }
}

#[cfg(test)]
mod tests {
    use crate::digest::DigestOneShot;
    use anyhow::bail;
    use num_traits::Zero;

    use super::*;

    #[test]
    fn challenge_36() -> Result<()> {
        let email = "anonymous@example.com";
        let good_password = "Let me in!";
        let bad_password = "Friend";

        for _ in 1..3 {
            let mut server = SrpServer::new(SRP_STANDARD.clone());
            let verifier = gen_srp_verifier(&SRP_STANDARD, good_password);
            server.save_verifier(email, verifier);

            for _ in 1..3 {
                let mut client = SrpClient::new(SRP_STANDARD.clone());

                let state = server.start_login(email, client.get_a())?;
                let response = client.process_params(&state.s, &state.b_pub, good_password);
                assert!(server.login(state, response));
            }

            for _ in 1..3 {
                let mut client = SrpClient::new(SRP_STANDARD.clone());

                let state = server.start_login(email, client.get_a())?;
                let response = client.process_params(&state.s, &state.b_pub, bad_password);
                assert!(!server.login(state, response));
            }
        }
        Ok(())
    }

    #[test]
    fn challenge_37() -> Result<()> {
        let email = "anonymous@example.com";
        let good_password = "Let me in!";

        for _ in 1..3 {
            let mut server = SrpServer::new(SRP_STANDARD.clone());
            let verifier = gen_srp_verifier(&SRP_STANDARD, good_password);
            server.save_verifier(email, verifier);

            let evil_a = [
                BigUint::zero(),
                SRP_STANDARD.n.clone(),
                &SRP_STANDARD.n + &SRP_STANDARD.n,
            ];
            for a_pub in &evil_a {
                let state = server.start_login(email, a_pub)?;
                let key = Sha256::oneshot_digest(&BigUint::zero().to_bytes_be());
                let mut hmac = Hmac::<Sha256>::init_new(&key);
                hmac.update(&state.s.to_bytes_be());
                let response = hmac.digest();
                assert!(server.login(state, response));
            }
        }
        Ok(())
    }

    #[test]
    fn simple_srp() -> Result<()> {
        let email = "anonymous@example.com";
        let good_password = "Let me in!";
        let bad_password = "Friend";

        for _ in 1..3 {
            let mut server = SimpleSrpServer::new(SRP_STANDARD.clone());
            let verifier = gen_srp_verifier(&SRP_STANDARD, good_password);
            server.save_verifier(email, verifier);

            for _ in 1..3 {
                let mut client = SimpleSrpClient::new(SRP_STANDARD.clone());

                let state = server.start_login(email, client.get_a())?;
                let response = client.process_params(&state.s, &state.b_pub, good_password);
                assert!(server.login(state, response));
            }

            for _ in 1..3 {
                let mut client = SimpleSrpClient::new(SRP_STANDARD.clone());

                let state = server.start_login(email, client.get_a())?;
                let response = client.process_params(&state.s, &state.b_pub, bad_password);
                assert!(!server.login(state, response));
            }
        }
        Ok(())
    }

    #[test]
    #[ignore = "slow"]
    fn challenge_38() -> Result<()> {
        let secret_password = crate::random_word_limit(250)?;
        println!("Looking for: {}", secret_password);

        let mut client = SimpleSrpClient::new(SRP_STANDARD.clone());
        let evil_b = rand_bigint(&SRP_STANDARD.n);
        let evil_b_pub = mod_exp(&SRP_STANDARD.g, &evil_b, &SRP_STANDARD.n);
        let evil_salt = rand_bigint(&SRP_STANDARD.n);

        let response = client.process_params(&evil_salt, &evil_b_pub, &secret_password);

        let mut digest = Sha256::default();
        let a = client.get_a();
        digest.update(&a.to_bytes_be());
        digest.update(&evil_b_pub.to_bytes_be());
        let u = BigUint::from_bytes_be(&digest.digest());
        let salt = evil_salt.to_bytes_be();
        let mut count = 0;
        for word in crate::read_file("words.txt")? {
            let word = word?;
            digest.update(&salt);
            digest.update(&word.as_bytes());
            let x = digest.digest();
            let x = BigUint::from_bytes_be(&x);
            let v = mod_exp(&SRP_STANDARD.g, &x, &SRP_STANDARD.n);
            let v_u = mod_exp(&v, &u, &SRP_STANDARD.n);
            let av_u = a * v_u;
            let s = mod_exp(&av_u, &evil_b, &SRP_STANDARD.n);
            digest.update(&s.to_bytes_be());
            let key = digest.digest();
            let mut hmac = Hmac::<Sha256>::init_new(&key);
            hmac.update(&salt);
            let guess = hmac.digest();
            if guess == response {
                assert_eq!(word, secret_password);
                return Ok(());
            }
            // if count % 10 == 0 {
                println!("Work({}): {}", count, word);
            // }
            count += 1;
        }
        bail!("Failed to find password");
    }
}
