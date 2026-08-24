use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;

use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::{
    core::{FilterVerdict, ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::config::parse_and_validate_plugin_config,
    utils::request,
};

pub const PLUGIN_NAME: &str = "request-id";
const PRIORITY: i32 = 12015;

// Note: Request ID is now stored directly in ProxyContext.request_id field
/// Default header name for request ID
const DEFAULT_REQUEST_ID_HEADER: &str = "X-Request-Id";
/// UUID algorithm identifier for request ID generation
const ALGORITHM_UUID: &str = "uuid";
/// Range ID algorithm identifier for request ID generation
const ALGORITHM_RANGE_ID: &str = "range_id";
/// Nano ID algorithm identifier for request ID generation
const ALGORITHM_NANOID: &str = "nanoid";
/// UUIDv7 algorithm identifier for request ID generation
const ALGORITHM_UUID_V7: &str = "uuidv7";
/// KSUID algorithm identifier for request ID generation
const ALGORITHM_KSUID: &str = "ksuid";
/// Default character set used for generating range-based request IDs
const DEFAULT_CHAR_SET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ0123456789";
/// Nano ID alphabet: 64 URL-safe characters, indexed by `random_byte & 63`.
const NANOID_ALPHABET: &str = "-_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Number of characters in a Nano ID request ID.
const NANOID_LENGTH: usize = 21;
/// KSUID base62 alphabet (values 0-9, 10-35, 36-61).
const KSUID_ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
/// Encoded KSUID length: 20 payload bytes become 27 base62 characters.
const KSUID_ENCODED_LENGTH: usize = 27;
/// KSUID's epoch: 2014-05-13T16:53:20Z.
const KSUID_EPOCH_SECS: u64 = 1_400_000_000;

/// Creates a Request ID plugin instance with the given configuration.
pub fn create_request_id_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginRequestID { config }))
}

/// `PLUGIN_META::validate` capability: parse the typed config and run its
/// validators WITHOUT constructing the plugin.
pub fn validate_request_id_config(cfg: &JsonValue) -> ProxyResult<()> {
    PluginConfig::try_from(cfg.clone())?;
    Ok(())
}

/// Configuration for the Request ID plugin.
#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    #[serde(default = "PluginConfig::default_header_name")]
    header_name: String,
    #[serde(default = "PluginConfig::default_include_in_response")]
    include_in_response: bool,
    #[serde(default = "PluginConfig::default_algorithm")]
    #[validate(custom(function = "PluginConfig::validate_algorithm"))]
    algorithm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(nested)]
    range_id: Option<RangeID>,
}

impl PluginConfig {
    fn default_header_name() -> String {
        DEFAULT_REQUEST_ID_HEADER.to_string()
    }

    fn default_include_in_response() -> bool {
        true
    }

    fn default_algorithm() -> String {
        ALGORITHM_UUID.to_string()
    }

    fn validate_algorithm(algorithm: &str) -> Result<(), ValidationError> {
        if [
            ALGORITHM_UUID,
            ALGORITHM_RANGE_ID,
            ALGORITHM_NANOID,
            ALGORITHM_UUID_V7,
            ALGORITHM_KSUID,
        ]
        .contains(&algorithm)
        {
            Ok(())
        } else {
            Err(ValidationError::new(
                "algorithm must be one of 'uuid', 'range_id', 'nanoid', 'uuidv7', or 'ksuid'",
            ))
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize, Validate)]
struct RangeID {
    #[serde(default = "RangeID::default_char_set")]
    #[validate(custom(function = "RangeID::validate_char_set"))]
    char_set: String,
    #[serde(default = "RangeID::default_length")]
    #[validate(custom(function = "RangeID::validate_length"))]
    length: u32,
}

impl RangeID {
    pub fn default_char_set() -> String {
        DEFAULT_CHAR_SET.to_string()
    }

    pub fn default_length() -> u32 {
        16
    }

    fn validate_char_set(char_set: &str) -> Result<(), ValidationError> {
        if char_set.chars().count() >= 6 {
            Ok(())
        } else {
            Err(ValidationError::new(
                "range_id.char_set must contain at least 6 characters",
            ))
        }
    }

    fn validate_length(length: u32) -> Result<(), ValidationError> {
        if length >= 6 {
            Ok(())
        } else {
            Err(ValidationError::new("range_id.length must be at least 6"))
        }
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Invalid request id plugin config")?;

        Ok(config)
    }
}

pub struct PluginRequestID {
    config: PluginConfig,
}

impl PluginRequestID {
    fn get_request_id(&self) -> String {
        match self.config.algorithm.as_str() {
            ALGORITHM_UUID => Uuid::new_v4().to_string(),
            ALGORITHM_RANGE_ID => self.get_range_id(),
            ALGORITHM_NANOID => Self::get_nanoid(),
            ALGORITHM_UUID_V7 => Uuid::now_v7().to_string(),
            ALGORITHM_KSUID => Self::get_ksuid(),
            _ => Uuid::new_v4().to_string(), // Fallback for invalid algorithm
        }
    }

    /// Generate a Nano ID request ID.
    ///
    /// Each character consumes one random byte masked with `& 63`; because the
    /// alphabet has exactly 64 entries this is unbiased (no modulo reduction).
    fn get_nanoid() -> String {
        (0..NANOID_LENGTH)
            .map(|_| {
                let index = (rand::random::<u8>() & 63) as usize;
                // The mask bounds `index` to the 64-entry alphabet, so `.get`
                // can never fail; `unwrap_or` keeps this panic-free in
                // production.
                NANOID_ALPHABET
                    .as_bytes()
                    .get(index)
                    .copied()
                    .unwrap_or(b'_') as char
            })
            .collect()
    }

    /// Generate a standard KSUID: seconds since the KSUID epoch followed by
    /// 16 random bytes, base62-encoded into 27 characters.
    fn get_ksuid() -> String {
        let unix_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let timestamp = unix_secs
            .saturating_sub(KSUID_EPOCH_SECS)
            .min(u32::MAX as u64) as u32;
        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);
        encode_ksuid(timestamp, &random)
    }

    fn get_range_id(&self) -> String {
        let range_id = self.config.range_id.as_ref();
        let char_set = range_id
            .map(|range_id| range_id.char_set.as_str())
            .filter(|char_set| !char_set.is_empty())
            .unwrap_or(DEFAULT_CHAR_SET);
        let chars: Vec<char> = char_set.chars().collect();

        // If char_set is empty, fallback to UUID
        if chars.is_empty() {
            log::warn!("Empty character set for range_id, falling back to UUID");
            return Uuid::new_v4().to_string();
        }

        let mut rng = rand::thread_rng();
        // chars is verified non-empty above, so choose() always succeeds.
        // Use unwrap_or to avoid .expect() in production code.
        let length = range_id
            .map(|range_id| range_id.length)
            .unwrap_or_else(RangeID::default_length);
        (0..length)
            .map(|_| chars.choose(&mut rng).copied().unwrap_or('?'))
            .collect()
    }
}

/// Encode a KSUID payload (4-byte big-endian timestamp + 16 random bytes) as
/// a 27-character, left-padded base62 string.
fn encode_ksuid(timestamp: u32, random: &[u8; 16]) -> String {
    let mut payload = [0u8; 20];
    payload[..4].copy_from_slice(&timestamp.to_be_bytes());
    payload[4..].copy_from_slice(random);

    // Long-division conversion from the 160-bit big-endian integer to base62.
    // `digits` is most-significant-first; `carry` starts as the appended
    // base-256 digit and propagates towards the most significant output digit.
    let mut digits = [0u8; KSUID_ENCODED_LENGTH];
    for &byte in &payload {
        let mut carry = byte as u16;
        for digit in digits.iter_mut().rev() {
            let value = *digit as u16 * 256 + carry;
            *digit = (value % 62) as u8;
            carry = value / 62;
        }
    }

    digits
        .iter()
        .map(|&digit| KSUID_ALPHABET[digit as usize] as char)
        .collect()
}

#[async_trait]
impl ProxyPlugin for PluginRequestID {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> Result<FilterVerdict> {
        // Retrieve request ID from header, or generate a new one
        let value =
            match request::get_req_header_value(session.req_header(), &self.config.header_name) {
                Some(s) => s.to_string(),
                None => {
                    let request_id = self.get_request_id();
                    session
                        .req_header_mut()
                        .insert_header(self.config.header_name.clone(), &request_id)
                        .map_err(|e| {
                            ProxyError::Internal(format!("Session insert header fail: {e}"))
                        })?;
                    request_id
                }
            };

        ctx.set_request_id(value);

        Ok(FilterVerdict::Continue)
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        if self.config.include_in_response {
            if let Some(request_id) = ctx.request_id() {
                upstream_response
                    .insert_header(self.config.header_name.clone(), request_id)
                    .map_err(|e| {
                        ProxyError::Internal(format!("Upstream response insert header fail: {e}"))
                    })?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_algorithm(algorithm: &str) -> PluginConfig {
        PluginConfig::try_from(serde_json::json!({ "algorithm": algorithm })).unwrap()
    }

    fn base62_decode(encoded: &str) -> Vec<u8> {
        let mut number: Vec<u8> = Vec::new();
        for ch in encoded.chars() {
            let digit = KSUID_ALPHABET
                .iter()
                .position(|&c| c == ch as u8)
                .expect("valid base62 digit") as u16;
            let mut carry = digit;
            for byte in number.iter_mut() {
                let value = *byte as u16 * 62 + carry;
                *byte = (value % 256) as u8;
                carry = value / 256;
            }
            while carry > 0 {
                number.push((carry % 256) as u8);
                carry /= 256;
            }
        }
        number.reverse();
        while number.len() < 20 {
            number.insert(0, 0);
        }
        number
    }

    #[test]
    fn default_algorithm_is_uuid() {
        let config = PluginConfig::try_from(serde_json::json!({})).unwrap();
        assert_eq!(config.algorithm, ALGORITHM_UUID);
        let plugin = PluginRequestID { config };
        assert!(Uuid::parse_str(&plugin.get_request_id()).is_ok());
    }

    #[test]
    fn nanoid_uses_expected_alphabet_and_length() {
        assert_eq!(NANOID_ALPHABET.len(), 64);
        let id = PluginRequestID::get_nanoid();
        assert_eq!(id.len(), NANOID_LENGTH);
        assert!(id.chars().all(|c| NANOID_ALPHABET.contains(c)));
    }

    #[test]
    fn uuidv7_generates_version_7_uuids() {
        let plugin = PluginRequestID {
            config: config_with_algorithm(ALGORITHM_UUID_V7),
        };
        let id = plugin.get_request_id();
        assert_eq!(Uuid::parse_str(&id).unwrap().get_version_num(), 7);
    }

    #[test]
    fn ksuid_is_27_chars_and_roundtrips_fixed_payload() {
        let timestamp: u32 = 300_000_000;
        let random = [0x5au8; 16];
        let encoded = encode_ksuid(timestamp, &random);
        assert_eq!(encoded.len(), KSUID_ENCODED_LENGTH);
        assert!(encoded.chars().all(|c| KSUID_ALPHABET.contains(&(c as u8))));

        let decoded = base62_decode(&encoded);
        assert_eq!(&decoded[..4], &timestamp.to_be_bytes());
        assert_eq!(&decoded[4..], &random);
    }

    #[test]
    fn ksuid_uses_standard_epoch() {
        let unix_secs = 1_700_000_000_u64;
        let timestamp = unix_secs.saturating_sub(KSUID_EPOCH_SECS) as u32;
        assert_eq!(timestamp, 300_000_000);
        let encoded = encode_ksuid(timestamp, &[0; 16]);
        assert_eq!(&base62_decode(&encoded)[..4], &timestamp.to_be_bytes());
    }

    #[test]
    fn ksuid_generation_is_valid_base62() {
        let plugin = PluginRequestID {
            config: config_with_algorithm(ALGORITHM_KSUID),
        };
        let id = plugin.get_request_id();
        assert_eq!(id.len(), KSUID_ENCODED_LENGTH);
        assert!(id.chars().all(|c| KSUID_ALPHABET.contains(&(c as u8))));
    }

    #[test]
    fn unknown_algorithm_is_rejected() {
        assert!(PluginConfig::try_from(serde_json::json!({ "algorithm": "snowflake" })).is_err());
    }

    #[test]
    fn range_id_length_must_be_at_least_six() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "algorithm": "range_id",
            "range_id": { "length": 5 }
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "algorithm": "range_id",
            "range_id": { "length": 6 }
        }))
        .is_ok());
    }

    #[test]
    fn range_id_char_set_must_have_at_least_six_chars() {
        assert!(PluginConfig::try_from(serde_json::json!({
            "algorithm": "range_id",
            "range_id": { "char_set": "abcde" }
        }))
        .is_err());
        assert!(PluginConfig::try_from(serde_json::json!({
            "algorithm": "range_id",
            "range_id": { "char_set": "abcdef" }
        }))
        .is_ok());
    }
}
