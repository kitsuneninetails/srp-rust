extern crate base64;
extern crate hex;
extern crate hmac;
extern crate md5;
extern crate num_bigint;
extern crate rand;
extern crate rustc_serialize;
extern crate sha2;

pub mod hex_string;
pub mod hash;

use hash::*;
use hex_string::HexString;
use num_bigint::BigUint;
use rand::{ThreadRng, Rng};
use std::ops::{Mul, Sub, Add};
use std::sync::{Arc, Mutex};

pub struct SrpVerifier {
    pub username: String,
    pub verifier: BigUint,
    pub salt: BigUint,
    _n: BigUint,
    _g: BigUint,
    _k: BigUint,
    _rng: Arc<Mutex<ThreadRng>>,
}

impl SrpVerifier {
    pub fn new(user: String, pass: String, mut rng: ThreadRng, g: u32) -> SrpVerifier {
        let n = HexString(
            "00c037c37588b4329887e61c2da3324b
             1ba4b81a63f9748fed2d8a410c2fc21b
             1232f0d3bfa024276cfd88448197aae4
             86a63bfca7b8bf7754dfb327c7201f6f
             d17fd7fd74158bd31ce772c9f5f8ab58
             4548a99a759b5a2c0532162b7b6218e8
             f142bce2c30d7784689a483e095e7016
             18437913a8c39c3dd0d4ca3c500b885f
             e3".into());

        let big_n = BigUint::from_bytes_be(n.as_bytes());

        let salt_hex = pad_hex(BigUint::from_bytes_be(gen_rand_bytes(16, &mut rng).as_slice()));
        let big_salt = BigUint::from_bytes_be(&salt_hex.as_bytes());

        let x_hex = hash_pass(user.clone(), pass, big_salt.clone());
        let big_x = BigUint::from_bytes_be(x_hex.as_bytes());

        let big_g = BigUint::new(vec![g]);

        let big_v: BigUint = big_g.modpow(&big_x, &big_n);

        let k_hex = hash(vec![big_n.to_bytes_be().as_slice(), big_g.to_bytes_be().as_slice()]);
        let big_k = BigUint::from_bytes_be(k_hex.as_bytes());

        SrpVerifier {
            username: user,
            verifier: big_v,
            salt: big_salt,
            _g: big_g,
            _n: big_n,
            _k: big_k,
            _rng: Arc::new(Mutex::new(rng)),
        }
    }

    pub fn session_token_client(&self) -> (BigUint, BigUint) {
        let a = BigUint::new(vec![self._rng.lock().unwrap().gen()]);
        (a.clone(), self._g.modpow(&a, &self._n))
    }

    pub fn session_token_server(&self) -> (BigUint, BigUint) {
        let b = BigUint::new(vec![self._rng.lock().unwrap().gen()]);
        (b.clone(), self._k.clone().mul(&self.verifier) + self._g.modpow(&b, &self._n))
    }

    pub fn session_key_client(&self, a: BigUint, _b: BigUint, pass: String) -> SrpSession {
        let _a = self._g.modpow(&a, &self._n);

        let u = BigUint::from_bytes_be(hash(vec![_a.to_bytes_be().as_slice(), _b.to_bytes_be().as_slice()]).as_bytes());

        let x_hex = hash_pass(self.username.clone(), pass, self.salt.clone());
        let big_x = BigUint::from_bytes_be(x_hex.as_bytes());

        let s_c1 = self._g.modpow(&big_x, &self._n);
        let s_c2 = self._k.clone().mul(&s_c1);
        let s_c3 = _b.clone().sub(&s_c2);
        let s_c4 = u.clone().mul(&big_x);
        let s_c5 = a.clone().add(&s_c4);
        let s_c = s_c3.modpow(&s_c5, &self._n);

        let k_c = BigUint::from_bytes_be(hash(vec![s_c.to_bytes_be().as_slice()]).as_bytes());

        SrpSession {
            pub_token: _a,
            local_token: a,
            session_key: k_c
        }
    }

    pub fn session_key_server(&self, b: BigUint, _a: BigUint) -> SrpSession {
        let _b = self._k.clone().mul(&self.verifier) + self._g.modpow(&b, &self._n);

        let u = BigUint::from_bytes_be(hash(vec![_a.to_bytes_be().as_slice(), _b.to_bytes_be().as_slice()]).as_bytes());

        let s_s1 = self.verifier.modpow(&u, &self._n);
        let s_s2 = _a.clone().mul(&s_s1);
        let s_s = s_s2.modpow(&b, &self._n);

        let k_s = BigUint::from_bytes_be(hash(vec![s_s.to_bytes_be().as_slice()]).as_bytes());

        SrpSession {
            pub_token: _b,
            local_token: b,
            session_key: k_s
        }
    }
}

pub struct SrpSession {
    pub session_key: BigUint,
    pub local_token: BigUint,
    pub pub_token: BigUint
}

impl SrpSession {
    pub fn gen_client_proof(&self, srv_token: BigUint) -> BigUint {
        BigUint::from_bytes_be(
            hash(vec![self.pub_token.to_bytes_be().as_slice(),
                      srv_token.to_bytes_be().as_slice(),
                      self.session_key.to_bytes_be().as_slice()]).as_bytes())
    }

    pub fn gen_server_proof(&self, cl_token: BigUint, cl_proof: BigUint) -> BigUint {
        BigUint::from_bytes_be(
            hash(vec![cl_token.to_bytes_be().as_slice(),
                      cl_proof.to_bytes_be().as_slice(),
                      self.session_key.to_bytes_be().as_slice()]).as_bytes())
    }

    pub fn verify_client_proof(&self, cl_token: BigUint, cl_proof: BigUint) -> bool {
        let srv_proof = BigUint::from_bytes_be(
            hash(vec![cl_token.to_bytes_be().as_slice(),
                      self.pub_token.to_bytes_be().as_slice(),
                      self.session_key.to_bytes_be().as_slice()]).as_bytes());
        srv_proof == cl_proof
    }

    pub fn verify_server_proof(&self, srv_token: BigUint, srv_proof: BigUint) -> bool {
        let orig_cl_proof = BigUint::from_bytes_be(
            hash(vec![self.pub_token.to_bytes_be().as_slice(),
                      srv_token.to_bytes_be().as_slice(),
                      self.session_key.to_bytes_be().as_slice()]).as_bytes());

        let cl_proof = BigUint::from_bytes_be(
            hash(vec![self.pub_token.to_bytes_be().as_slice(),
                      orig_cl_proof.to_bytes_be().as_slice(),
                      self.session_key.to_bytes_be().as_slice()]).as_bytes());
        srv_proof == cl_proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_verify() {
        let username = "test_user".to_string();
        let mut rng = rand::thread_rng();
        let pass = gen_rand_base64(40, &mut rng);
        let srp_v = SrpVerifier::new(username, pass.clone(), rng, 2);

        let (a, _a) = srp_v.session_token_client();
        let (b, _b) = srp_v.session_token_server();

        let cl_sess = srp_v.session_key_client(a, _b.clone(), pass);
        let srv_sess = srp_v.session_key_server(b, _a.clone());

        let cl_proof = cl_sess.gen_client_proof(_b.clone());

        assert!(srv_sess.verify_client_proof(_a.clone(), cl_proof.clone()));

        let srv_proof = srv_sess.gen_server_proof(_a, cl_proof);

        assert!(cl_sess.verify_server_proof(_b, srv_proof));

    }
}
