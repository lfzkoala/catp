use axum::{extract::Json, http::StatusCode, routing::post, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use catp_authorization::AuthorizationPublicInputs;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct VerifyRequest {
    /// Base64-encoded proof bytes from `prove_authorization`.
    proof: String,
    #[serde(rename = "publicInputs")]
    public_inputs: PublicInputsRequest,
}

#[derive(Deserialize)]
struct PublicInputsRequest {
    #[serde(rename = "policyCommitment")]
    policy_commitment: String,
    #[serde(rename = "actionType")]
    action_type: U64String,
    #[serde(rename = "actionProtocol")]
    action_protocol: [U64String; 4],
    #[serde(rename = "actionToken")]
    action_token: [U64String; 4],
    #[serde(rename = "actionValue")]
    action_value: U64String,
    #[serde(rename = "currentTimestamp")]
    current_timestamp: U64String,
    #[serde(rename = "cumulativeSpend")]
    cumulative_spend: U64String,
}

#[derive(Deserialize, Clone)]
#[serde(untagged)]
enum U64String {
    Number(u64),
    String(String),
}

impl U64String {
    fn parse(self, field: &str) -> Result<u64, String> {
        match self {
            Self::Number(n) => Ok(n),
            Self::String(s) => s
                .parse::<u64>()
                .map_err(|e| format!("{field} must be a u64: {e}")),
        }
    }
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn handle_verify(Json(req): Json<VerifyRequest>) -> (StatusCode, Json<VerifyResponse>) {
    let proof_bytes = match STANDARD.decode(&req.proof) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyResponse {
                    valid: false,
                    error: Some(format!("invalid base64: {e}")),
                }),
            );
        }
    };

    let policy_commitment =
        match catp_verify::parse_policy_commitment(&req.public_inputs.policy_commitment) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(VerifyResponse {
                        valid: false,
                        error: Some(e.to_string()),
                    }),
                );
            }
        };
    let current_timestamp = match req
        .public_inputs
        .current_timestamp
        .clone()
        .parse("currentTimestamp")
    {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyResponse {
                    valid: false,
                    error: Some(e),
                }),
            );
        }
    };
    let cumulative_spend = match req
        .public_inputs
        .cumulative_spend
        .clone()
        .parse("cumulativeSpend")
    {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyResponse {
                    valid: false,
                    error: Some(e),
                }),
            );
        }
    };
    let action_type = match req.public_inputs.action_type.clone().parse("actionType") {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyResponse {
                    valid: false,
                    error: Some(e),
                }),
            );
        }
    };
    let action_value = match req.public_inputs.action_value.clone().parse("actionValue") {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerifyResponse {
                    valid: false,
                    error: Some(e),
                }),
            );
        }
    };
    let mut action_protocol = [0u64; 4];
    for (i, input) in req.public_inputs.action_protocol.iter().enumerate() {
        action_protocol[i] = match input.clone().parse("actionProtocol") {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(VerifyResponse {
                        valid: false,
                        error: Some(e),
                    }),
                );
            }
        };
    }
    let mut action_token = [0u64; 4];
    for (i, input) in req.public_inputs.action_token.iter().enumerate() {
        action_token[i] = match input.clone().parse("actionToken") {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(VerifyResponse {
                        valid: false,
                        error: Some(e),
                    }),
                );
            }
        };
    }
    let public_inputs = AuthorizationPublicInputs {
        policy_commitment,
        action_type,
        action_protocol,
        action_token,
        action_value,
        current_timestamp,
        cumulative_spend,
    };

    match catp_verify::verify(&proof_bytes, &public_inputs) {
        Ok(valid) => (StatusCode::OK, Json(VerifyResponse { valid, error: None })),
        Err(e) => (
            StatusCode::OK,
            Json(VerifyResponse {
                valid: false,
                error: Some(e.to_string()),
            }),
        ),
    }
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3030);

    let app = Router::new().route("/verify", post(handle_verify));
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("catp-verify listening on {addr}");
    axum::serve(listener, app).await.unwrap();
}
