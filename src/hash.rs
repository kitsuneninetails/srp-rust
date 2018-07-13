use base64;
use hex_string::HexString;
use num_bigint::BigUint;
use rand::{ThreadRng, Rng};
use rand::distributions::Standard;
use rustc_serialize::hex::{FromHex, ToHex};
use sha2::{Digest, Sha256};

pub fn gen_rand_bytes(num: usize, rng: &mut ThreadRng) -> Vec<u8> {
    rng.sample_iter(&Standard).take(num).collect()
}

pub fn gen_rand_base64(len: usize, rng: &mut ThreadRng) -> String {
    let bytes = gen_rand_bytes(len, rng);
    base64::encode(bytes.as_slice())
}

pub fn pad_hex(input: BigUint) -> HexString {
    let hash_str = HexString::from(input.to_bytes_be());
    if hash_str.len() % 2 == 1 {
        HexString(format!("0{}", hash_str.0.to_ascii_lowercase()))
    } else if hash_str.len() > 0 &&
        "89abcdef".find(hash_str.0.chars().next().unwrap().to_ascii_lowercase()).is_some() {
        HexString(format!("00{}", hash_str.0.to_ascii_lowercase()))
    } else {
        HexString(hash_str.0.to_ascii_lowercase())
    }
}

pub fn rpad_string(hstr: HexString, pad_len: usize, pad_char: char) -> HexString {
    let num_pad = pad_len - hstr.len();
    let num_pad: usize = if num_pad > 0 { num_pad } else { 0 };
    HexString(format!("{}{}", pad_char.to_string().repeat(num_pad), hstr))
}

pub fn hash(input: Vec<&[u8]>) -> Vec<u8> {
    let mut full_vec = Vec::new();
    for v in input.iter() {
        full_vec.extend_from_slice(v);
    }
    rpad_string(HexString(Sha256::digest(full_vec.as_slice()).to_hex()), 64, '0').from_hex().unwrap()
}

pub fn hash_pass(user: String, pass: String, salt: BigUint) -> Vec<u8> {
    let up_hash = hash(vec![user.as_bytes(), ":".as_bytes(), pass.as_bytes()]);
    let mut salt_up_hash = Vec::new();
    salt_up_hash.extend_from_slice(salt.to_bytes_be().as_slice());
    salt_up_hash.extend_from_slice(up_hash.as_slice());
    hash(vec![salt_up_hash.as_slice()])
}

