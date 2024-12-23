use base64::prelude::*;
use chrono::{DateTime, Utc};
use cryptosystem::{PublicKey, SecretKey, Signature, SigningCryptosystem};
use error::{GetBlockError, ParseError, ProofError};
use serde::{Deserialize, Serialize};
use ureq::serde_json::Value;

mod error;

/// A time-based proof using the hash of the most recent block in the Bitcoin blockchain to prove
/// it occurred after a certain time.
///
/// If the internal message should be kept secret, it should be encrypted (and possibly have the
/// plaintext separately signed) before being passed to this system.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Proof<S: SigningCryptosystem> {
    block_hash: String,
    message: String,
    signature: Signature<S>,
}
impl<S: SigningCryptosystem> Proof<S> {
    /// Creates a new proof on the given message, using the given secret key and the latest block
    /// in the Bitcoin blockchain.
    pub fn new_latest(message: String, secret_key: &SecretKey<S>) -> Result<Self, ProofError<S>> {
        let block_hash = get_latest_block_hash()?;
        let signature = secret_key
            .sign((&message, &block_hash))
            .map_err(ProofError::SignFailed)?;
        Ok(Self {
            block_hash,
            message,
            signature,
        })
    }
    /// Creates a new proof on the given message, using the given secret key and block hash, which
    /// is *not* checked for validity, however an invalid block hash will not validate properly
    /// later!
    pub fn new_manual(
        message: String,
        block_hash: &str,
        secret_key: &SecretKey<S>,
    ) -> Result<Self, ProofError<S>> {
        let signature = secret_key
            .sign((&message, block_hash))
            .map_err(ProofError::SignFailed)?;
        Ok(Self {
            block_hash: block_hash.to_string(),
            message,
            signature,
        })
    }
    /// Validates this proof, returning `Ok(Ok(ts))` with the timestamp of the block it asserts on
    /// (i.e. the earliest time the proof could possibly have been created), or an error if it is
    /// invalid or the timestamp couldn't be fetched. The outer error indicates proof invalidity,
    /// and the inner indicates a failure to fetch the block's details (though this could indicate
    /// the proof's block hash is altogether invalid, too!).
    pub fn validate(
        &self,
        public_key: &PublicKey<S>,
    ) -> Result<Result<DateTime<Utc>, GetBlockError>, ProofError<S>> {
        public_key
            .verify(&self.signature, (&self.message, &self.block_hash))
            .map_err(ProofError::ValidateFailed)?;
        Ok(get_block_time(&self.block_hash))
    }

    /// Converts this proof to a string.
    pub fn to_string(&self) -> String {
        let bytes = bincode::serialize(&self).unwrap();
        BASE64_STANDARD.encode(&bytes)
    }

    /// Parses a proof from the given string.
    pub fn parse(proof_str: &str) -> Result<Self, ParseError> {
        let bytes = BASE64_STANDARD
            .decode(proof_str)
            .map_err(ParseError::DecodeFailed)?;
        bincode::deserialize(&bytes).map_err(ParseError::DeserFailed)
    }

    /// Returns the message in this proof.
    pub fn message(&self) -> &String {
        &self.message
    }
}

/// Gets the hash of the latest block on the Bitcoin blockchain, cross-referencing from two
/// different APIs to give greater confidence.
fn get_latest_block_hash() -> Result<String, GetBlockError> {
    // Check blockchain.info first
    let resp = ureq::get("https://blockchain.info/latestblock")
        .call()?
        .into_json::<Value>()
        .map_err(|source| GetBlockError::ParseFailed(source))?;
    let hash_1 = resp
        .get("hash")
        .ok_or(GetBlockError::BadFormat)?
        .as_str()
        .ok_or(GetBlockError::BadFormat)?
        .to_string();

    // Next, check btcscan.org
    let hash_2 = ureq::get("https://btcscan.org/api/blocks/tip/hash")
        .call()?
        .into_string()
        .map_err(|source| GetBlockError::ParseFailed(source))?;

    if hash_1 != hash_2 {
        return Err(GetBlockError::HashMismatch { hash_1, hash_2 });
    }

    Ok(hash_1)
}

/// Gets the UTC timestamp at which the Bitcoin block with the given hash was created.
fn get_block_time(hash: &str) -> Result<DateTime<Utc>, GetBlockError> {
    // Get the block data from blockchain.info first
    let resp = ureq::get(&format!("https://blockchain.info/rawblock/{hash}"))
        .call()?
        .into_json::<Value>()
        .map_err(|source| GetBlockError::ParseFailed(source))?;
    let time_1 = resp
        .get("time")
        .ok_or(GetBlockError::BadFormat)?
        .as_u64()
        .ok_or(GetBlockError::BadFormat)?;

    // Then cross-reference with btcscan.org
    let resp = ureq::get(&format!("https://btcscan.org/api/block/{hash}"))
        .call()?
        .into_json::<Value>()
        .map_err(|source| GetBlockError::ParseFailed(source))?;
    let time_2 = resp
        .get("timestamp")
        .ok_or(GetBlockError::BadFormat)?
        .as_u64()
        .ok_or(GetBlockError::BadFormat)?;

    if time_1 != time_2 {
        return Err(GetBlockError::TimestampMismatch {
            time_1,
            time_2,
            hash: hash.to_string(),
        });
    }

    // And convert it to a DateTime
    Ok(DateTime::from_timestamp(time_1 as i64, 0)
        .ok_or(GetBlockError::BadTimestamp { ts: time_1 })?)
}
