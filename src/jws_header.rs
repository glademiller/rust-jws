#![allow(dead_code)]

extern crate serde;
extern crate serde_json;

use std::collections::BTreeMap;
use self::serde::{Serialize, Serializer};
use self::serde::ser::MapVisitor;
use self::serde_json::{Value, to_value, from_value};

#[derive(Debug, PartialEq, Clone)]
pub enum ALGORITHM {
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

impl Serialize for ALGORITHM {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {
            let string_value = match self {
                &ALGORITHM::HS256 => "HS256",
                &ALGORITHM::HS384 => "HS384",
                &ALGORITHM::HS512 => "HS512",
                &ALGORITHM::RS256 => "RS256",
                &ALGORITHM::RS384 => "RS384",
                &ALGORITHM::RS512 => "RS512",
                &ALGORITHM::ES256 => "ES256",
                &ALGORITHM::ES384 => "ES384",
                &ALGORITHM::ES512 => "ES512"
            };
            try!(serializer.serialize_str(string_value));
            Ok(())
    }
}

impl serde::Deserialize for ALGORITHM {
    fn deserialize<D>(deserializer: &mut D) -> Result<ALGORITHM, D::Error>
        where D: serde::de::Deserializer
    {
        struct AlgVisitor;

        impl serde::de::Visitor for AlgVisitor {
            type Value = ALGORITHM;

            fn visit_str<E>(&mut self, value: &str) -> Result<ALGORITHM, E>
                where E: serde::de::Error
            {
                match value {
                    "HS256" => Ok(ALGORITHM::HS256),
                    "HS384" => Ok(ALGORITHM::HS384),
                    "HS512" => Ok(ALGORITHM::HS512),
                    "RS256" => Ok(ALGORITHM::RS256),
                    "RS384" => Ok(ALGORITHM::RS384),
                    "RS512" => Ok(ALGORITHM::RS512),
                    "ES256" => Ok(ALGORITHM::ES256),
                    "ES384" => Ok(ALGORITHM::ES384),
                    "ES512" => Ok(ALGORITHM::ES512),
                    _ => Ok(ALGORITHM::HS256) //@TODO return an error
                }
            }
        }
        deserializer.deserialize_str(AlgVisitor)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Header {
    pub alg: ALGORITHM,
    pub jku: Option<String>,
    pub kid: Option<String>,
    pub x5u: Option<String>,
    pub x5t: Option<String>,
    pub typ: Option<String>,
    values: BTreeMap<String, Value>,
}

const RESERVED_HEADERS: [&'static str; 6] = ["typ", "alg", "jku", "kid", "x5u", "x5t"];

impl Serialize for Header {
    fn serialize<S>(&self, serializer: &mut S) -> Result<(), S::Error>
        where S: serde::Serializer
    {

        struct HeaderVisitor {
            header: Header,
        }
        impl MapVisitor for HeaderVisitor {
            #[inline]
            fn visit<S>(&mut self, serializer: &mut S) -> Result<Option<()>, S::Error>
                where S: Serializer
            {
                try!(serializer.serialize_map_elt("alg", self.header.alg.clone()));
                if let Some(ref typ) = self.header.typ {
                    try!(serializer.serialize_map_elt("typ", typ.as_str()));
                }
                if let Some(ref jku) = self.header.jku {
                    try!(serializer.serialize_map_elt("jku", jku.as_str()));
                }
                if let Some(ref kid) = self.header.kid {
                    try!(serializer.serialize_map_elt("kid", kid.as_str()));
                }
                if let Some(ref x5u) = self.header.x5u {
                    try!(serializer.serialize_map_elt("x5u", x5u.as_str()));
                }
                if let Some(ref x5t) = self.header.x5t {
                    try!(serializer.serialize_map_elt("x5t", x5t.as_str()));
                }
                for (key, value) in self.header
                    .values
                    .iter()
                    .filter(|&(key, _)| !RESERVED_HEADERS.contains(&key.as_str())) {
                    try!(serializer.serialize_map_elt(key, value));
                }
                return Ok(None);
            }

            #[inline]
            fn len(&self) -> Option<usize> {
                None
            }
        }
        return serializer.serialize_map(HeaderVisitor { header: self.clone() });
    }
}

enum HeaderField { TYP, ALG, JKU, KID, X5U, X5T, Custom(String) }

impl serde::Deserialize for HeaderField {
    fn deserialize<D>(deserializer: &mut D) -> Result<HeaderField, D::Error>
        where D: serde::de::Deserializer
    {
        struct FieldVisitor;

        impl serde::de::Visitor for FieldVisitor {
            type Value = HeaderField;

            fn visit_str<E>(&mut self, value: &str) -> Result<HeaderField, E>
                where E: serde::de::Error
            {
                match value {
                    "typ" => Ok(HeaderField::TYP),
                    "alg" => Ok(HeaderField::ALG),
                    "jku" => Ok(HeaderField::JKU),
                    "kid" => Ok(HeaderField::KID),
                    "x5u" => Ok(HeaderField::X5U),
                    "x5t" => Ok(HeaderField::X5T),
                    _ => {
                        Ok(HeaderField::Custom(value.to_owned()))
                    }
                }
            }
        }

        deserializer.deserialize(FieldVisitor)
    }
}

struct HeaderVisitor;

impl serde::de::Visitor for HeaderVisitor {
    type Value = Header;

    fn visit_map<V>(&mut self, mut visitor: V) -> Result<Header, V::Error>
        where V: serde::de::MapVisitor
    {
        let mut typ = None;
        let mut alg = None;
        let mut jku = None;
        let mut kid = None;
        let mut x5u = None;
        let mut x5t = None;
        let mut values = BTreeMap::new();

        while let Some(key) = try!(visitor.visit_key()) {
            match key {
                HeaderField::TYP => typ = Some(try!(visitor.visit_value())),
                HeaderField::ALG => alg = Some(try!(visitor.visit_value())),
                HeaderField::JKU => jku = Some(try!(visitor.visit_value())),
                HeaderField::KID => kid = Some(try!(visitor.visit_value())),
                HeaderField::X5U => x5u = Some(try!(visitor.visit_value())),
                HeaderField::X5T => x5t = Some(try!(visitor.visit_value())),
                HeaderField::Custom(k) => {
                    let value: Value = try!(visitor.visit_value());
                    values.insert(k, value);
                }
            }
        }

        let alg = match alg {
            Some(a) => a,
            None => {
                return Err(serde::de::Error::missing_field("alg"));
            }
        };

        try!(visitor.end());

        Ok(Header {
            typ: typ,
            alg: alg,
            jku: jku,
            kid: kid,
            x5u: x5u,
            x5t: x5t,
            values: values,
        })
    }
}

impl serde::Deserialize for Header {
    fn deserialize<D>(deserializer: &mut D) -> Result<Header, D::Error>
        where D: serde::Deserializer
    {

        deserializer.deserialize_map(HeaderVisitor)
    }
}

impl Header {
    pub fn new() -> Header {
        Header {
            alg: ALGORITHM::HS256,
            typ: None,
            jku: None,
            kid: None,
            x5u: None,
            x5t: None,
            values: BTreeMap::new(),
        }
    }

    pub fn set<T: Serialize>(&mut self, key: &str, value: T) {
        if !RESERVED_HEADERS.contains(&key) {
            self.values.insert(key.to_owned(), to_value(&value));
        }
    }

    pub fn get<T: serde::de::Deserialize>(&self, key: &str) -> Option<T> {
       self.values.get(key).and_then(|v| from_value(v.clone()).ok())
    }

    pub fn to_json(&self) -> Result<String, serde_json::error::Error> {
        serde_json::to_string(self)
    }
}

#[test]
fn setting_reserved_headers_as_custom_does_nothing() {
    let mut h = Header::new();
    h.typ = Some("JWT".to_owned());
    h.set("typ", 245);
    let result: Option<u64> = h.get("typ");
    assert!(result.is_none());
    assert_eq!(h.typ.unwrap(), "JWT");
}

#[test]
fn you_can_set_and_retrieve_custom_headers() {
    let mut h = Header::new();
    h.set("DOG", 245);
    let result: Option<u64> = h.get("DOG");
    assert_eq!(result.unwrap(), 245);
}

#[test]
fn retrieving_a_custom_header_that_is_not_set_returns_none() {
    let h = Header::new();
    let result: Option<u64> = h.get("DOG");
    assert!(result.is_none());
}

#[test]
fn headers_can_be_serialized_to_and_from_json_preserving_all_fields() {
    let mut h = Header::new();
    h.typ = Some("JWT".to_owned());
    h.jku = Some("WHERE".to_owned());
    h.kid = Some("KEY".to_owned());
    h.x5u = Some("X5U".to_owned());
    h.x5t = Some("X5T".to_owned());
    h.set("ISS", "Something");
    h.set("RAT", 98);
    let json = serde_json::to_string(&h).unwrap();
    let new_h: Header = serde_json::from_str(&json).unwrap();

    let new_iss: String = new_h.get("ISS").unwrap();
    let old_iss: String = h.get("ISS").unwrap();
    assert_eq!(new_iss, old_iss);

    let new_rat: u64 = new_h.get("RAT").unwrap();
    let old_rat: u64 = h.get("RAT").unwrap();
    assert_eq!(new_rat, old_rat);

    assert_eq!(new_h.typ.unwrap(), h.typ.unwrap());
    assert_eq!(new_h.alg, h.alg);
    assert_eq!(new_h.jku.unwrap(), h.jku.unwrap());
    assert_eq!(new_h.kid.unwrap(), h.kid.unwrap());
    assert_eq!(new_h.x5u.unwrap(), h.x5u.unwrap());
    assert_eq!(new_h.x5t.unwrap(), h.x5t.unwrap());
}
