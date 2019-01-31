//Zei error types

use std::{fmt, error};
use hex::FromHexError;
use schnorr::errors::SchnorrError;
use organism_utils::crypto::secretbox::errors::SecretBoxError;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    //Invalid format is passed to function
    BadSecretError,
    TxProofError,
    NotEnoughFunds,
    DeserializationError,
    NoneError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Error::BadSecretError => "Given Secret Key is not good",
            Error::TxProofError => "Could not create transation due to range proof error",
            Error::NotEnoughFunds => "There is not enough funds to make this transaction",
            Error::DeserializationError => "Could not deserialize object",
            Error::NoneError => "Could not unwrap option due to None value",
        })
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::BadSecretError => "Given Secret Key is not good",
            Error::TxProofError => "Could not create transation due to range proof error",
            Error::NotEnoughFunds => "There is not enough funds to make this transaction",
            Error::DeserializationError => "Could not deserialize object",
            Error::NoneError => "Could not unwrap option due to None value",
        }
    }
}

impl From<FromHexError> for Error {
    fn from(_error: FromHexError) -> Self {
        Error::DeserializationError
    }
}

impl From<serde_json::Error> for Error {
    fn from(_error: serde_json::Error) -> Self {
        Error::DeserializationError
    }
}

impl From<SchnorrError> for Error {
    fn from(_error: SchnorrError) -> Self {
        Error::DeserializationError
    }
}

impl From<SecretBoxError> for Error {
    fn from(_error: SecretBoxError) -> Self {
        Error::DeserializationError
    }
}

impl From<bulletproofs::ProofError> for Error {
    fn from(_error: bulletproofs::ProofError) -> Self {
        Error::DeserializationError
    }
}

impl From<std::option::NoneError> for Error {
    fn from(_error: std::option::NoneError) -> Self {
        Error::NoneError
    }
}

