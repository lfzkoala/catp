use axum::{extract::Json, http::StatusCode, routing::post, Router};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct VerifyRequest {
    /// Base64-encoded proof bytes from `prove_authorization`.
    proof: String,
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

    match catp_verify::verify(&proof_bytes) {
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
