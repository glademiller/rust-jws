#![allow(dead_code)]
extern crate openssl;

use std::io::Error;

use self::openssl::crypto::pkey::PKey;
use self::openssl::crypto::hash;
use self::openssl::crypto::hmac::hmac;

enum ALGORITHMS {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
}

pub fn sign_pk256(key: PKey, payload: &[u8]) -> Result<Vec<u8>, Error> {
    sign(hash::Type::SHA256, key, payload)
}

pub fn sign_pk384(key: PKey, payload: &[u8]) -> Result<Vec<u8>, Error> {
    sign(hash::Type::SHA384, key, payload)
}

pub fn sign_pk512(key: PKey, payload: &[u8]) -> Result<Vec<u8>, Error> {
    sign(hash::Type::SHA512, key, payload)
}

pub fn verify_pk256(key: PKey, hash: &[u8], payload: &[u8]) -> bool {
    verify(hash::Type::SHA256, key, hash, payload)
}

pub fn verify_pk384(key: PKey, hash: &[u8], payload: &[u8]) -> bool {
    verify(hash::Type::SHA256, key, hash, payload)
}

pub fn verify_pk512(key: PKey, hash: &[u8], payload: &[u8]) -> bool {
    verify(hash::Type::SHA256, key, hash, payload)
}

fn sign(hash_type: hash::Type, key: PKey, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let digest = hash::hash(hash_type, payload);
    Ok(key.sign_with_hash(digest.as_slice(), hash_type))
}

fn verify(hash_type: hash::Type, key: PKey, hash: &[u8], payload: &[u8]) -> bool {
    key.verify_with_hash(hash, payload, hash_type)
}

pub fn hmac_256(key: &[u8], payload: &[u8]) -> Vec<u8> {
    hmac(hash::Type::SHA256, key, payload)
}

pub fn hmac_384(key: &[u8], payload: &[u8]) -> Vec<u8> {
    hmac(hash::Type::SHA384, key, payload)
}

pub fn hmac_512(key: &[u8], payload: &[u8]) -> Vec<u8> {
    hmac(hash::Type::SHA512, key, payload)
}
