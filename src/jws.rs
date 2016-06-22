#![allow(dead_code)]
extern crate rustc_serialize;
extern crate serde_json;
extern crate openssl;
extern crate rand;

use jws_header::Header;
use jws_header::ALGORITHM;
use claims::Claims;

use self::rustc_serialize::base64;
use self::rustc_serialize::base64::FromBase64;
use self::rustc_serialize::base64::ToBase64;

use self::openssl::crypto::pkey::PKey;
use std::io::{Error, ErrorKind};

use signing;

use std::str;

const BASE64_CONFIG: base64::Config = base64::Config {
    char_set: base64::CharacterSet::UrlSafe,
    newline: base64::Newline::LF,
    pad: false,
    line_length: None
};

fn base64_url_encode(value: String) -> String {
    base64_url_encode_bytes(value.as_bytes())
}


fn base64_url_encode_bytes(bytes: &[u8]) -> String {
    bytes.to_base64(BASE64_CONFIG)
}

#[derive(Debug, PartialEq, Clone)]
pub enum JWSBody {
    Custom { value: Vec<u8>, typ: Option<String> },
    JWT { claims: Claims }
}

#[derive(Debug, PartialEq, Clone)]
pub struct JWS {
    header: Header,
    body: JWSBody
}

impl JWS {
    fn from_claims(header: Header, claims: Claims) -> JWS {
        JWS {
            header: header,
            body: JWSBody::JWT { claims: claims }
        }
    }

    fn from_custom(header: Header, value: Vec<u8>) -> JWS {
        let typ = header.typ.clone();
        JWS {
            header: header,
            body: JWSBody::Custom { value: value, typ: typ }
        }
    }

    fn decode(value: String, secret: &[u8], algorithm: ALGORITHM, decode_claims: bool) -> Option<JWS> {
        //Result<JWS, Error> {
        let parts: Vec<&str> = value.split('.').collect();
        //@TODO verify the number of parts and stop the unwrapping
        let header = parts[0].from_base64().unwrap();
        let header = str::from_utf8(header.as_slice()).unwrap();
        let payload: String = format!("{}.{}", parts[0], parts[1]);
        let signature = parts[2];

        let header: Header = serde_json::from_str(&header).unwrap();

        if header.alg != algorithm || !JWS::verify_signature(payload.as_str(), signature, secret, algorithm) {
            return None;
        }

        let body = parts[1].from_base64().unwrap();
        if decode_claims {
            let body = str::from_utf8(body.as_slice()).unwrap();
            let claims: Claims = serde_json::from_str(&body).unwrap();
            Some(JWS::from_claims(header, claims))
        } else {
            Some(JWS::from_custom(header, body))
        }
    }

    fn decode_jwt(value: String, secret: &[u8], algorithm: ALGORITHM) -> Option<JWS> {
        JWS::decode(value, secret, algorithm, true)
    }

    fn verify_signature(payload: &str, signature: &str, mut secret: &[u8], algorithm: ALGORITHM) -> bool {
        let sig_matches = match algorithm {
            ALGORITHM::RS256 => {
                let key = PKey::private_key_from_pem( & mut secret).unwrap(); //@TODO unwrap
                signing::verify_pk256(key, signature.as_bytes(), payload.as_bytes())
            },
            ALGORITHM::RS384 => {
                let key = PKey::private_key_from_pem( & mut secret).unwrap(); //@TODO unwrap
                signing::verify_pk384(key, signature.as_bytes(), payload.as_bytes())
            },
            ALGORITHM::RS512 => {
                let key = PKey::private_key_from_pem( & mut secret).unwrap(); //@TODO unwrap
                signing::verify_pk512(key, signature.as_bytes(), payload.as_bytes())
            },
            ALGORITHM::HS256 => base64_url_encode_bytes(signing::hmac_256( & mut secret, payload.as_bytes()).as_slice()) == signature,
            ALGORITHM::HS384 => base64_url_encode_bytes(signing::hmac_384( &mut secret, payload.as_bytes()).as_slice()) == signature,
            ALGORITHM::HS512 => base64_url_encode_bytes(signing::hmac_512( & mut secret, payload.as_bytes()).as_slice()) == signature,
            _ => false
        };
        sig_matches
    }

    fn get_body_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        match self.body {
            JWSBody::Custom { ref value, .. } => Ok(value.clone()),
            JWSBody::JWT { ref claims } => claims.to_json().map(|v: String| -> Vec<u8> { v.into_bytes() })
        }
    }

    fn get_body_typ(&self) -> Option<String> {
        match self.body {
            JWSBody::Custom { ref typ, .. } => typ.clone(),
            JWSBody::JWT { .. } => Some("JWT".to_owned())
        }
    }
    fn serialize_payload(&self) -> String {
        let mut final_header = self.header.clone();
        final_header.typ = self.get_body_typ();
        let header_json = final_header.to_json().unwrap(); //@TODO REMOVE UNWRAP
        let claims_json = self.get_body_bytes().unwrap();
        format!("{}.{}", base64_url_encode(header_json), base64_url_encode_bytes(claims_json.as_slice()))
    }

    fn encode(&self, mut secret: &[u8], alg: ALGORITHM) -> String {
        let payload = self.serialize_payload();
        let signature = match alg {
            ALGORITHM::RS256 => {
                let key = PKey::private_key_from_pem(&mut secret).unwrap(); //@TODO unwrap
                signing::sign_pk256(key, payload.as_bytes()).unwrap()
            },
            ALGORITHM::RS384 => {
                let key = PKey::private_key_from_pem(&mut secret).unwrap(); //@TODO unwrap
                signing::sign_pk384(key, payload.as_bytes()).unwrap()
            },
            ALGORITHM::RS512 => {
                let key = PKey::private_key_from_pem(&mut secret).unwrap(); //@TODO unwrap
                signing::sign_pk512(key, payload.as_bytes()).unwrap()
            },
            ALGORITHM::HS256 => signing::hmac_256(secret, payload.as_bytes()),
            ALGORITHM::HS384 => signing::hmac_384(secret, payload.as_bytes()),
            ALGORITHM::HS512 => signing::hmac_512(secret, payload.as_bytes()),
            _ => signing::hmac_256(secret, payload.as_bytes())
        };
        let b64_sig = base64_url_encode_bytes(signature.as_slice());
        format!("{}.{}", payload, b64_sig)
    }
}

#[test]
fn test_serialize() {
    let mut claims = Claims::new();
    claims.iss = Some("DISPOSITION".to_owned());
    claims.jti = Some("vpmli2IC9NRZ1EVkLEgJpg".to_owned());
    claims.set("orgid", 1701);
    claims.set("stasub", "darkwingduck");
    claims.set("crmuid", "C680AFBC-B8E4-E511-80DC-FC15B4284AE0");
    claims.set("crmtype", "Dynamics");
    claims.set("idmid", 1);
    claims.exp = Some(1473164280);
    claims.iat = Some(1457396280);
    let mut header = Header::new();
    header.set("iss", "DISPOSITION");
    header.alg = ALGORITHM::HS256;
    let t = JWS::from_claims(header, claims);

    let key = "secret";
    let encoded = t.encode(key.as_bytes(), ALGORITHM::HS256);
    println!("{}", encoded);
    let decoded = JWS::decode_jwt(encoded, key.as_bytes(), ALGORITHM::HS256).unwrap();
    println!("{}", decoded.header.get::<String>("iss").unwrap());
}
