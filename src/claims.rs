#![allow(dead_code)]

use std::collections::BTreeMap;
use serde;
use serde_json;
use serde::Serialize;
use serde_json::{Value, to_value, from_value};
use std::result;
use error::Result;


#[derive(Debug, PartialEq, Clone)]
pub struct Claims {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<u64>,
    pub nbf: Option<u64>,
    pub iat: Option<u64>,
    pub jti: Option<String>,
    claims: BTreeMap<String, Value>,
}

const RESERVED_CLAIMS: [&'static str; 7] = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"];

impl Serialize for Claims {
    fn serialize<S>(&self, serializer: &mut S) -> result::Result<(), S::Error>
        where S: serde::Serializer
    {
        let mut state = try!(serializer.serialize_map(None));
        for (key, value) in self.claims.iter()
            .filter(|&(key, _)| !RESERVED_CLAIMS.contains(&key.as_str())) {
            try!(serializer.serialize_map_key(&mut state, key));
            try!(serializer.serialize_map_value(&mut state, value));
        }
        if let Some(ref iss) = self.iss {
            try!(serializer.serialize_map_key(&mut state, "iss"));
            try!(serializer.serialize_map_value(&mut state, iss.as_str()));
        }
        if let Some(ref sub) = self.sub {
            try!(serializer.serialize_map_key(&mut state, "sub"));
            try!(serializer.serialize_map_value(&mut state, sub.as_str()));
        }
        if let Some(ref aud) = self.aud {
            try!(serializer.serialize_map_key(&mut state, "aud"));
            try!(serializer.serialize_map_value(&mut state, aud.as_str()));
        }
        if let Some(ref exp) = self.exp {
            try!(serializer.serialize_map_key(&mut state, "exp"));
            try!(serializer.serialize_map_value(&mut state, exp));
        }
        if let Some(ref nbf) = self.nbf {
            try!(serializer.serialize_map_key(&mut state, "nbf"));
            try!(serializer.serialize_map_value(&mut state, nbf));
        }
        if let Some(ref iat) = self.iat {
            try!(serializer.serialize_map_key(&mut state, "iat"));
            try!(serializer.serialize_map_value(&mut state, iat));
        }
        if let Some(ref jti) = self.jti {
            try!(serializer.serialize_map_key(&mut state, "jti"));
            try!(serializer.serialize_map_value(&mut state, jti.as_str()));
        }

        serializer.serialize_map_end(state)
    }
}

enum ClaimsField { ISS, SUB, AUD, EXP, NBF, IAT, JTI, Custom(String) }

impl serde::Deserialize for ClaimsField {
    fn deserialize<D>(deserializer: &mut D) -> result::Result<ClaimsField, D::Error>
        where D: serde::de::Deserializer
    {
        struct FieldVisitor;

        impl serde::de::Visitor for FieldVisitor {
            type Value = ClaimsField;

            fn visit_str<E>(&mut self, value: &str) -> result::Result<ClaimsField, E>
                where E: serde::de::Error
            {
                match value {
                    "iss" => Ok(ClaimsField::ISS),
                    "sub" => Ok(ClaimsField::SUB),
                    "aud" => Ok(ClaimsField::AUD),
                    "exp" => Ok(ClaimsField::EXP),
                    "nbf" => Ok(ClaimsField::NBF),
                    "iat" => Ok(ClaimsField::IAT),
                    "jti" => Ok(ClaimsField::JTI),
                    _ => {
                        Ok(ClaimsField::Custom(value.to_owned()))
                    }
                }
            }
        }

        deserializer.deserialize(FieldVisitor)
    }
}

struct ClaimsVisitor;

impl serde::de::Visitor for ClaimsVisitor {
    type Value = Claims;

    fn visit_map<V>(&mut self, mut visitor: V) -> result::Result<Claims, V::Error>
        where V: serde::de::MapVisitor
    {
        let mut iss = None;
        let mut sub = None;
        let mut aud = None;
        let mut exp = None;
        let mut nbf = None;
        let mut iat = None;
        let mut jti = None;
        let mut claims = BTreeMap::new();

        while let Some(key) = try!(visitor.visit_key()) {
            match key {
                ClaimsField::ISS => iss = Some(try!(visitor.visit_value())),
                ClaimsField::SUB => sub = Some(try!(visitor.visit_value())),
                ClaimsField::AUD => aud = Some(try!(visitor.visit_value())),
                ClaimsField::EXP => exp = Some(try!(visitor.visit_value())),
                ClaimsField::NBF => nbf = Some(try!(visitor.visit_value())),
                ClaimsField::IAT => iat = Some(try!(visitor.visit_value())),
                ClaimsField::JTI => jti = Some(try!(visitor.visit_value())),
                ClaimsField::Custom(k) => {
                    let value: Value = try!(visitor.visit_value());
                    claims.insert(k, value);
                }
            }
        }

        try!(visitor.end());

        Ok(Claims {
            iss: iss,
            sub: sub,
            aud: aud,
            exp: exp,
            nbf: nbf,
            iat: iat,
            jti: jti,
            claims: claims
        })
    }
}

impl serde::Deserialize for Claims {
    fn deserialize<D>(deserializer: &mut D) -> result::Result<Claims, D::Error>
        where D: serde::Deserializer
    {

        deserializer.deserialize_map(ClaimsVisitor)
    }
}

impl Claims {
    pub fn new() -> Claims {
        Claims {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            claims: BTreeMap::new(),
        }
    }

    pub fn set<T: Serialize>(&mut self, key: &str, value: T) {
        if !RESERVED_CLAIMS.contains(&key) {
            self.claims.insert(key.to_owned(), to_value(&value));
        }
    }

    pub fn get<T: serde::de::Deserialize>(&self, key: &str) -> Option<T> {
       self.claims.get(key).and_then(|v| from_value(v.clone()).ok())
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(try!(serde_json::to_string(self)))
    }
}

#[test]
fn setting_reserved_claims_as_custom_does_nothing() {
    let mut c = Claims::new();
    c.iss = Some("Dyn".to_owned());
    c.set("iss", 245);
    let result: Option<u64> = c.get("iss");
    assert!(result.is_none());
    assert_eq!(c.iss, Some("Dyn".to_owned()));
}

#[test]
fn you_can_set_and_retrieve_custom_claims() {
    let mut c = Claims::new();
    c.set("DOG", 245);
    let result: Option<u64> = c.get("DOG");
    assert_eq!(result.unwrap(), 245);
}

#[test]
fn retrieving_a_custom_claim_that_is_not_set_returns_none() {
    let c = Claims::new();
    let result: Option<u64> = c.get("DOG");
    assert!(result.is_none());
}

#[test]
fn claims_can_be_serialized_to_and_from_json_preserving_all_fields() {
    let mut h = Claims::new();
    h.iss = Some("WHERE".to_owned());
    h.sub = Some("KEY".to_owned());
    h.aud = Some("X5U".to_owned());
    h.exp = Some(2000);
    h.nbf = Some(3000);
    h.iat = Some(45000);
    h.jti = Some("DKDK".to_owned());
    h.set("ISS", "Something");
    h.set("RAT", 98);
    let json = serde_json::to_string(&h).unwrap();
    let new_h: Claims = serde_json::from_str(&json).unwrap();

    let new_iss: String = new_h.get("ISS").unwrap();
    let old_iss: String = h.get("ISS").unwrap();
    assert_eq!(new_iss, old_iss);

    let new_rat: u64 = new_h.get("RAT").unwrap();
    let old_rat: u64 = h.get("RAT").unwrap();
    assert_eq!(new_rat, old_rat);

    assert_eq!(new_h.iss.unwrap(), h.iss.unwrap());
    assert_eq!(new_h.sub.unwrap(), h.sub.unwrap());
    assert_eq!(new_h.aud.unwrap(), h.aud.unwrap());
    assert_eq!(new_h.exp.unwrap(), h.exp.unwrap());
    assert_eq!(new_h.nbf.unwrap(), h.nbf.unwrap());
    assert_eq!(new_h.iat.unwrap(), h.iat.unwrap());
    assert_eq!(new_h.jti.unwrap(), h.jti.unwrap());
}
