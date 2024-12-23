use cryptosystem::{CryptoError, SigningCryptosystem};
use thiserror::Error;

/// Errors that can occur when getting details about the latest block, or a specific block.
#[derive(Error, Debug)]
pub enum GetBlockError {
    #[error("request to get block failed")]
    RequestFailed(#[from] ureq::Error),
    #[error("failed to parse block response")]
    ParseFailed(#[source] std::io::Error),
    #[error("found unexpected block data format")]
    BadFormat,
    #[error("hashes from different blockchain apis did not match on the latest block (try again in a moment)")]
    HashMismatch { hash_1: String, hash_2: String },
    #[error(
        "block timstamps from different blockchain apis did not match on block with hash {hash}"
    )]
    TimestampMismatch {
        time_1: u64,
        time_2: u64,
        hash: String,
    },
    #[error("blockchain apis all returned unparseable timestamp {ts}")]
    BadTimestamp { ts: u64 },
}

/// Errors that can occur when creating and validating proofs.
#[derive(Error, Debug)]
pub enum ProofError<S: SigningCryptosystem + 'static> {
    #[error("failed to sign proof")]
    SignFailed(#[source] CryptoError<S::Error>),
    #[error("failed to validate proof")]
    ValidateFailed(#[source] CryptoError<S::Error>),
    #[error(transparent)]
    GetBlockError(#[from] GetBlockError),
}

/// Errors that can occur while parsing a proof from a string.
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("failed to decode proof from base64")]
    DecodeFailed(#[source] base64::DecodeError),
    #[error("failed to deserialize proof")]
    DeserFailed(#[source] bincode::Error),
}
