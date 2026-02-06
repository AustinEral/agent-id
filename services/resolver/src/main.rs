//! DID Resolver HTTP Service
//!
//! Provides HTTP endpoints for registering and resolving DID Documents.

use aip_core::DidDocument;
use aip_resolver::Resolver;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use clap::Parser;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "aip-resolver")]
#[command(about = "AIP DID Resolver Service")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "8500")]
    port: u16,
}

type AppState = Arc<Resolver>;

/// Register a new DID Document.
async fn register_document(
    State(resolver): State<AppState>,
    Json(document): Json<DidDocument>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    let did = document.id.clone();

    resolver
        .register(document)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    println!("Registered: {}", did);

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "registered",
            "did": did
        })),
    ))
}

/// Resolve a DID to its document.
async fn resolve_document(
    State(resolver): State<AppState>,
    Path(did): Path<String>,
) -> Result<Json<DidDocument>, (StatusCode, String)> {
    // URL decode the DID (colons may be encoded)
    let did = urlencoding::decode(&did)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
        .into_owned();

    let document = resolver
        .resolve(&did)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    Ok(Json(document))
}

/// Update an existing DID Document.
async fn update_document(
    State(resolver): State<AppState>,
    Json(document): Json<DidDocument>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let did = document.id.clone();

    resolver
        .update(document)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    println!("Updated: {}", did);

    Ok(Json(serde_json::json!({
        "status": "updated",
        "did": did
    })))
}

/// List all registered DIDs.
async fn list_documents(State(resolver): State<AppState>) -> Json<serde_json::Value> {
    let dids = resolver.list();
    Json(serde_json::json!({
        "count": dids.len(),
        "dids": dids
    }))
}

/// Health check.
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "aip-resolver"
    }))
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let resolver = Arc::new(Resolver::new());

    let app = Router::new()
        .route("/health", get(health))
        .route("/documents", post(register_document))
        .route("/documents", get(list_documents))
        .route("/documents/{did}", get(resolve_document))
        .route("/documents/update", post(update_document))
        .with_state(resolver);

    let addr = format!("0.0.0.0:{}", args.port);
    println!("AIP Resolver Service");
    println!("  Listening on: http://{}", addr);
    println!();
    println!("Endpoints:");
    println!("  POST /documents         - Register a DID Document");
    println!("  GET  /documents/{{did}}    - Resolve a DID");
    println!("  GET  /documents         - List all DIDs");
    println!("  POST /documents/update  - Update a DID Document");
    println!();

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
