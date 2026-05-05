use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct U64Visitor;

    impl<'de> de::Visitor<'de> for U64Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a u64 number or decimal string")
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            value.parse::<u64>().map_err(E::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&value)
        }
    }

    deserializer.deserialize_any(U64Visitor)
}

/// Type of action an agent can perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u64)]
pub enum ActionType {
    Swap = 0,
    Transfer = 1,
    Deposit = 2,
    Withdraw = 3,
}

impl ActionType {
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

/// A proposed action the agent wants to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action_type: ActionType,
    /// Protocol address as a 32-byte identifier.
    pub protocol: [u8; 32],
    /// Token address as a 32-byte identifier.
    pub token: [u8; 32],
    /// Value in base units (e.g., USDC smallest unit).
    #[serde(deserialize_with = "deserialize_u64")]
    pub value: u64,
}

/// An authorization policy granting an agent permission to act within constraints.
/// All fields are private inputs to the circuit except `policy_commitment`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationPolicy {
    /// Allowed action type (single value; multi-set deferred to Phase 2).
    pub allowed_action: ActionType,
    /// Allowed protocol (single value).
    pub allowed_protocol: [u8; 32],
    /// Allowed token (single value).
    pub allowed_token: [u8; 32],
    /// Maximum value per transaction.
    #[serde(deserialize_with = "deserialize_u64")]
    pub max_value_per_tx: u64,
    /// Maximum cumulative value across all transactions.
    #[serde(deserialize_with = "deserialize_u64")]
    pub max_value_total: u64,
    /// Policy validity start (Unix timestamp).
    #[serde(deserialize_with = "deserialize_u64")]
    pub valid_from: u64,
    /// Policy validity end (Unix timestamp).
    #[serde(deserialize_with = "deserialize_u64")]
    pub valid_until: u64,
}

impl AuthorizationPolicy {
    /// Compute the native commitment to this policy using SHA-256.
    /// Inside the ZK circuit, Poseidon is used instead (see circuit.rs TODO).
    pub fn commitment(&self) -> catp_primitives::Commitment {
        use catp_primitives::CommitmentScheme;
        CommitmentScheme::commit_fields(&[
            &self.allowed_action.as_u64().to_le_bytes(),
            &self.allowed_protocol,
            &self.allowed_token,
            &self.max_value_per_tx.to_le_bytes(),
            &self.max_value_total.to_le_bytes(),
            &self.valid_from.to_le_bytes(),
            &self.valid_until.to_le_bytes(),
        ])
    }
}
