#![allow(dead_code)]
use serde_json;
use std::result::Result as StdResult;
use std::convert::From;
use std::str::Utf8Error;
use std::io;
use openssl::ssl::error::SslError;
use rustc_serialize::base64::FromBase64Error;

quick_error! {
    #[derive(Debug)]
    pub enum Error {
    	// Custom(err: String) {
    	// 	from(err: String)
    	// }
    	SigningError(err: io::Error) {
    		description(err.description())
    		display("{}", err)
    	}
    	KeyError(err: SslError) {
    		from()
    		description(err.description())
    		display("{}", err)
    	}
    	JWSInvalidSignature {
    		description("The signature is invalid.")
    		display("The signature is invaild.")
    	}
    	Base64DecodeError(err: FromBase64Error) {
    		from()
    		description(err.description())
    		display("{}", err)
    	}
    	Utf8Error(err: Utf8Error) {
    		from()
    		description(err.description())
    		display("{}", err)
    	}
        SerdeJson(err: serde_json::Error) {
        	from()
        	description(err.description())
        	display("{}", err)
        }
    }
}

pub type Result<T> = StdResult<T, Error>;