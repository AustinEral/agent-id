//! Transparency Log HTTP Service
//!
//! Provides HTTP endpoints for the append-only identity event log.

use aip_core::RootKey;
use aip_log::{InclusionProof, LogEntry, TransparencyLog};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "aip-log")]
#[command(about = "AIP Transparency Log Service")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "8600")]
    port: u16,
}

struct AppState {
    log: TransparencyLog,
    #[allow(dead_code)]
    operator_key: RootKey,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LogStatus {
    size: u64,
    root_hash: String,
    last_hash: String,
}

#[derive(Deserialize)]
struct DidQuery {
    did: Option<String>,
}

/// Get log status.
async fn get_status(State(state): State<Arc<AppState>>) -> Json<LogStatus> {
    Json(LogStatus {
        size: state.log.size(),
        root_hash: state.log.root_hash(),
        last_hash: state.log.last_hash(),
    })
}

/// Append a new entry to the log.
async fn append_entry(
    State(state): State<Arc<AppState>>,
    Json(entry): Json<LogEntry>,
) -> Result<Json<LogEntry>, (StatusCode, String)> {
    let appended = state
        .log
        .append(entry)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    println!(
        "Appended entry #{}: {} ({})",
        appended.sequence,
        appended.subject_did,
        format!("{:?}", appended.event_type).to_lowercase()
    );

    Ok(Json(appended))
}

/// Get an entry by sequence number.
async fn get_entry(
    State(state): State<Arc<AppState>>,
    Path(sequence): Path<u64>,
) -> Result<Json<LogEntry>, (StatusCode, String)> {
    let entry = state
        .log
        .get(sequence)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok(Json(entry))
}

/// Get entries (optionally filtered by DID).
async fn get_entries(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DidQuery>,
) -> Json<Vec<LogEntry>> {
    let entries = if let Some(did) = query.did {
        state.log.get_by_did(&did)
    } else {
        // Return last 100 entries
        let size = state.log.size();
        let start = size.saturating_sub(100);
        (start..size)
            .filter_map(|i| state.log.get(i).ok())
            .collect()
    };

    Json(entries)
}

/// Get inclusion proof for an entry.
async fn get_proof(
    State(state): State<Arc<AppState>>,
    Path(sequence): Path<u64>,
) -> Result<Json<InclusionProof>, (StatusCode, String)> {
    let proof = state
        .log
        .prove(sequence)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok(Json(proof))
}

/// Verify an inclusion proof.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest {
    entry_hash: String,
    proof: InclusionProof,
}

#[derive(Serialize)]
struct VerifyResponse {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

async fn verify_proof(Json(req): Json<VerifyRequest>) -> Json<VerifyResponse> {
    match req.proof.verify(&req.entry_hash) {
        Ok(()) => Json(VerifyResponse {
            valid: true,
            error: None,
        }),
        Err(e) => Json(VerifyResponse {
            valid: false,
            error: Some(e.to_string()),
        }),
    }
}

/// Health check.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "aip-log"
    }))
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Generate operator key (in production, load from secure storage)
    let operator_key = RootKey::generate();
    let operator_did = operator_key.did();

    let state = Arc::new(AppState {
        log: TransparencyLog::with_operator(RootKey::generate()), // Use a separate key for signing
        operator_key,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(get_status))
        .route("/entries", get(get_entries))
        .route("/entries", post(append_entry))
        .route("/entries/{sequence}", get(get_entry))
        .route("/entries/{sequence}/proof", get(get_proof))
        .route("/verify", post(verify_proof))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", args.port);
    println!("AIP Transparency Log Service");
    println!("  Operator DID: {}", operator_did);
    println!("  Listening on: http://{}", addr);
    println!();
    println!("Endpoints:");
    println!("  GET  /status              - Log status (size, root hash)");
    println!("  POST /entries             - Append entry");
    println!("  GET  /entries             - List entries (?did=xxx to filter)");
    println!("  GET  /entries/{{seq}}       - Get entry by sequence");
    println!("  GET  /entries/{{seq}}/proof - Get inclusion proof");
    println!("  POST /verify              - Verify an inclusion proof");
    println!();

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
