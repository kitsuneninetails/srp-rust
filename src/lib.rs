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
use rustc_serialize::hex::FromHex;
use std::ops::{Mul, Sub, Add};

pub struct SrpVerifier {
    pub username: String,
    pub verifier: BigUint,
    pub salt: BigUint,
    _n: BigUint,
    _g: BigUint,
    _k: BigUint,
}

impl SrpVerifier {
    pub fn new(user: String, pass: String, rng: &mut ThreadRng, g: u32) -> SrpVerifier {
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

        let big_n = BigUint::from_bytes_be(n.from_hex().unwrap().as_slice());

        let salt_hex = pad_hex(BigUint::from_bytes_be(gen_rand_bytes(16, rng).as_slice()));
        let big_salt = BigUint::from_bytes_be(salt_hex.from_hex().unwrap().as_slice());

        let x_hash = hash_pass(user.clone(), pass, big_salt.clone());
        let big_x = BigUint::from_bytes_be(x_hash.as_slice());

        let big_g = BigUint::new(vec![g]);

        let big_v: BigUint = big_g.modpow(&big_x, &big_n);

        let k_hash = hash(vec![big_n.to_bytes_be().as_slice(), big_g.to_bytes_be().as_slice()]);
        let big_k = BigUint::from_bytes_be(k_hash.as_slice());

        SrpVerifier {
            username: user,
            verifier: big_v,
            salt: big_salt,
            _g: big_g,
            _n: big_n,
            _k: big_k,
        }
    }

    pub fn new_client(&self, rng: &mut ThreadRng) -> SrpClient {
        let a = BigUint::new(vec![rng.gen()]);
        // A = g^a
        let _a = self._g.modpow(&a, &self._n);
        SrpClient::new(_a,
                       a,
                       self.username.clone(),
                       self.salt.clone(),
                       self._k.clone(),
                       self._g.clone(),
                       self._n.clone())
    }

    pub fn new_server(&self, rng: &mut ThreadRng) -> SrpServer {
        let b = BigUint::new(vec![rng.gen()]);
        // B = k*v + g^b
        let _b = self._k.clone().mul(&self.verifier) + self._g.modpow(&b, &self._n);
        SrpServer::new(_b,
                       b,
                       self.verifier.clone(),
                       self._n.clone())
    }
}

pub struct SrpClient {
    local_token: BigUint,
    pub pub_token: BigUint,
    username: String,
    salt: BigUint,
    k: BigUint,
    g: BigUint,
    _n: BigUint,
}

impl SrpClient {
    pub fn new(pub_token: BigUint,
               local_token: BigUint,
               username: String,
               salt: BigUint,
               k: BigUint,
               g: BigUint,
               _n: BigUint) -> Self {
        SrpClient {
            pub_token,
            local_token,
            username,
            salt,
            k,
            g,
            _n
        }
    }

    pub fn new_session(&self, srv_pub_tkn: BigUint, pass: String) -> SrpClientSession {
        // u = H(A|B)
        let u = BigUint::from_bytes_be(hash(vec![self.pub_token.to_bytes_be().as_slice(),
                                                 srv_pub_tkn.to_bytes_be().as_slice()]).as_slice());

        // x = H(H(s)|U|":"|P)
        let x_hash = hash_pass(self.username.clone(), pass, self.salt.clone());
        let x = BigUint::from_bytes_be(x_hash.as_slice());

        // g^x
        let s_c1 = self.g.modpow(&x, &self._n);
        // k*g^x
        let s_c2 = self.k.clone().mul(&s_c1);
        // B - (k*g^x)
        let s_c3 = srv_pub_tkn.clone().sub(&s_c2);
        // u * x
        let s_c4 = u.clone().mul(&x);
        // a + (H(A|B) * H(U|P|s))
        let s_c5 = self.local_token.clone().add(&s_c4);
        // (B - (k*g^x))^(a + (u * x))
        let s_c = s_c3.modpow(&s_c5, &self._n);

        SrpClientSession::new(BigUint::from_bytes_be(hash(vec![s_c.to_bytes_be().as_slice()]).as_slice()),
                              self.pub_token.clone(),
                              srv_pub_tkn)
    }
}

pub struct SrpClientSession {
    session_key: BigUint,
    pub_token: BigUint,
    server_pub_token: BigUint,
}

impl SrpClientSession {
    pub fn new(session_key: BigUint, pub_token: BigUint, server_pub_token: BigUint) -> Self {
        SrpClientSession {
            session_key,
            pub_token,
            server_pub_token,
        }
    }

    pub fn gen_check(&self) -> BigUint {
        BigUint::from_bytes_be(
            hash(vec![self.pub_token.to_bytes_be().as_slice(),
                      self.server_pub_token.to_bytes_be().as_slice(),
                      self.session_key.to_bytes_be().as_slice()]).as_slice())
    }

    pub fn verify_check(&self, check_value: BigUint) -> bool {
        let exp_srv_check = BigUint::from_bytes_be(
            hash(vec![self.pub_token.to_bytes_be().as_slice(),
                      self.gen_check().to_bytes_be().as_slice(),
                      self.session_key.to_bytes_be().as_slice()]).as_slice());
        check_value == exp_srv_check
    }
}

pub struct SrpServer {
    local_token: BigUint,
    pub pub_token: BigUint,
    verifier: BigUint,
    _n: BigUint,
}

impl SrpServer {
    pub fn new(pub_token: BigUint,
               local_token: BigUint,
               verifier: BigUint,
               _n: BigUint) -> Self {
        SrpServer {
            pub_token,
            local_token,
            verifier,
            _n
        }
    }

    pub fn new_session(&self, cl_pub_token: BigUint) -> SrpServerSession {
        // u = H(A|B)
        let u = BigUint::from_bytes_be(hash(vec![cl_pub_token.to_bytes_be().as_slice(),
                                                 self.pub_token.to_bytes_be().as_slice()]).as_slice());

        // v^u
        let s_s1 = self.verifier.modpow(&u, &self._n);
        // A * v^u
        let s_s2 = cl_pub_token.clone().mul(&s_s1);
        // (A * v^u)^b
        let s_s = s_s2.modpow(&self.local_token, &self._n);

        SrpServerSession::new(BigUint::from_bytes_be(hash(vec![s_s.to_bytes_be().as_slice()]).as_slice()),
                              self.pub_token.clone(),
                              cl_pub_token)
    }
}

pub struct SrpServerSession {
    session_key: BigUint,
    client_pub_token: BigUint,
    pub_token: BigUint,
}

impl SrpServerSession {
    pub fn new(session_key: BigUint,
               pub_token: BigUint,
               client_pub_token: BigUint) -> Self {
        SrpServerSession {
            session_key,
            pub_token,
            client_pub_token
        }
    }

    pub fn gen_check(&self, client_check: BigUint) -> BigUint {
        BigUint::from_bytes_be(
            hash(vec![self.client_pub_token.to_bytes_be().as_slice(),
                      client_check.to_bytes_be().as_slice(),
                      self.session_key.to_bytes_be().as_slice()]).as_slice())
    }

    pub fn verify_check(&self, check_val: BigUint) -> bool {
        let exp_srv_check = BigUint::from_bytes_be(
            hash(vec![self.client_pub_token.to_bytes_be().as_slice(),
                      self.pub_token.to_bytes_be().as_slice(),
                      self.session_key.to_bytes_be().as_slice()]).as_slice());
        exp_srv_check == check_val
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_verify() {
        let username = "test_user".to_string();
        let mut rng = rand::thread_rng();
        let pass = "testPass".to_string();
        let srp_v = SrpVerifier::new(username, pass.clone(), &mut rng, 2);

        let srp_cl = srp_v.new_client(&mut rng);
        let srp_srv = srp_v.new_server(&mut rng);

        println!("client token = {}", srp_cl.pub_token);
        println!("serv token = {}", srp_srv.pub_token);

        let cl_sess = srp_cl.new_session(srp_srv.pub_token.clone(), pass);
        let srv_sess = srp_srv.new_session(srp_cl.pub_token.clone());

        let cl_proof = cl_sess.gen_check();

        assert!(srv_sess.verify_check(cl_proof.clone()));

        let srv_proof = srv_sess.gen_check(cl_proof);

        assert!(cl_sess.verify_check(srv_proof));

    }
}
