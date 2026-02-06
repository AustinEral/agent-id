//! Trust Relay Service
//!
//! A service for publishing and querying trust statements between agents.
//! Part of the Agent Identity Protocol Layer 2.

#[cfg(test)]
use aip_core::RootKey;
use aip_trust::{TrustStatement, BlockStatement};
#[cfg(test)]
use aip_trust::BlockSeverity;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

/// Trust Relay configuration.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Listen address.
    pub listen_addr: SocketAddr,
    /// Maximum statements per identity (spam prevention).
    pub max_statements_per_identity: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            listen_addr: ([0, 0, 0, 0], 8082).into(),
            max_statements_per_identity: 1000,
        }
    }
}

/// Stored trust statement with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredStatement {
    pub statement: TrustStatement,
    pub received_at: i64,
}

/// Stored block statement with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredBlock {
    pub statement: BlockStatement,
    pub received_at: i64,
}

/// Graph edge for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub issuer: String,
    pub subject: String,
    pub trust_score: f64,
    pub timestamp: i64,
}

/// Graph response for API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphResponse {
    pub center: String,
    pub depth: usize,
    pub nodes: Vec<String>,
    pub edges: Vec<GraphEdge>,
}

/// In-memory storage for trust data.
#[derive(Debug, Default)]
pub struct TrustStore {
    /// Trust statements indexed by issuer DID.
    statements_by_issuer: HashMap<String, Vec<StoredStatement>>,
    /// Trust statements indexed by subject DID.
    statements_by_subject: HashMap<String, Vec<StoredStatement>>,
    /// Block statements indexed by issuer DID.
    blocks_by_issuer: HashMap<String, Vec<StoredBlock>>,
    /// Block statements indexed by subject DID.
    blocks_by_subject: HashMap<String, Vec<StoredBlock>>,
    /// Statement count per issuer (for rate limiting).
    statement_counts: HashMap<String, usize>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trust statement.
    pub fn add_statement(&mut self, statement: TrustStatement, max_per_identity: usize) -> Result<(), String> {
        let issuer = &statement.issuer;
        
        // Check rate limit
        let count = self.statement_counts.get(issuer).copied().unwrap_or(0);
        if count >= max_per_identity {
            return Err("Rate limit exceeded".to_string());
        }

        let stored = StoredStatement {
            statement: statement.clone(),
            received_at: chrono::Utc::now().timestamp_millis(),
        };

        // Index by issuer
        self.statements_by_issuer
            .entry(statement.issuer.clone())
            .or_default()
            .push(stored.clone());

        // Index by subject
        self.statements_by_subject
            .entry(statement.subject.clone())
            .or_default()
            .push(stored);

        // Update count
        *self.statement_counts.entry(issuer.clone()).or_default() += 1;

        Ok(())
    }

    /// Add a block statement.
    pub fn add_block(&mut self, statement: BlockStatement) {
        let stored = StoredBlock {
            statement: statement.clone(),
            received_at: chrono::Utc::now().timestamp_millis(),
        };

        // Index by issuer
        self.blocks_by_issuer
            .entry(statement.issuer.clone())
            .or_default()
            .push(stored.clone());

        // Index by subject
        self.blocks_by_subject
            .entry(statement.subject.clone())
            .or_default()
            .push(stored);
    }

    /// Get statements issued by a DID.
    pub fn get_by_issuer(&self, issuer: &str) -> Vec<&StoredStatement> {
        self.statements_by_issuer
            .get(issuer)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get statements about a subject DID.
    pub fn get_by_subject(&self, subject: &str) -> Vec<&StoredStatement> {
        self.statements_by_subject
            .get(subject)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Get statement from issuer about subject.
    pub fn get_statement(&self, issuer: &str, subject: &str) -> Option<&StoredStatement> {
        self.statements_by_issuer
            .get(issuer)?
            .iter()
            .find(|s| s.statement.subject == subject)
    }

    /// Get blocks issued by a DID.
    pub fn get_blocks_by_issuer(&self, issuer: &str) -> Vec<&StoredBlock> {
        self.blocks_by_issuer
            .get(issuer)
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    }

    /// Check if subject is blocked by issuer.
    pub fn is_blocked(&self, issuer: &str, subject: &str) -> bool {
        self.blocks_by_issuer
            .get(issuer)
            .map(|blocks| blocks.iter().any(|b| b.statement.subject == subject))
            .unwrap_or(false)
    }

    /// Build a trust graph centered on a DID.
    pub fn build_graph(&self, center: &str, depth: usize) -> GraphResponse {
        let mut nodes = std::collections::HashSet::new();
        let mut edges = Vec::new();
        let mut seen_edges = std::collections::HashSet::new();
        
        self.collect_graph_data(center, depth, &mut nodes, &mut edges, &mut seen_edges, &mut std::collections::HashSet::new());
        
        GraphResponse {
            center: center.to_string(),
            depth,
            nodes: nodes.into_iter().collect(),
            edges,
        }
    }

    fn collect_graph_data(
        &self,
        did: &str,
        remaining_depth: usize,
        nodes: &mut std::collections::HashSet<String>,
        edges: &mut Vec<GraphEdge>,
        seen_edges: &mut std::collections::HashSet<String>,
        visited: &mut std::collections::HashSet<String>,
    ) {
        if remaining_depth == 0 || visited.contains(did) {
            return;
        }
        visited.insert(did.to_string());
        nodes.insert(did.to_string());

        // Add outgoing edges (statements issued by this DID)
        if let Some(statements) = self.statements_by_issuer.get(did) {
            for stored in statements {
                let stmt = &stored.statement;
                let edge_key = format!("{}:{}", stmt.issuer, stmt.subject);
                nodes.insert(stmt.subject.clone());
                if seen_edges.insert(edge_key) {
                    edges.push(GraphEdge {
                        issuer: stmt.issuer.clone(),
                        subject: stmt.subject.clone(),
                        trust_score: stmt.assessment.overall_trust,
                        timestamp: stmt.timestamp.timestamp_millis(),
                    });
                }
                
                self.collect_graph_data(&stmt.subject, remaining_depth - 1, nodes, edges, seen_edges, visited);
            }
        }

        // Add incoming edges (statements about this DID)
        if let Some(statements) = self.statements_by_subject.get(did) {
            for stored in statements {
                let stmt = &stored.statement;
                let edge_key = format!("{}:{}", stmt.issuer, stmt.subject);
                nodes.insert(stmt.issuer.clone());
                if seen_edges.insert(edge_key) {
                    edges.push(GraphEdge {
                        issuer: stmt.issuer.clone(),
                        subject: stmt.subject.clone(),
                        trust_score: stmt.assessment.overall_trust,
                        timestamp: stmt.timestamp.timestamp_millis(),
                    });
                }
                
                self.collect_graph_data(&stmt.issuer, remaining_depth - 1, nodes, edges, seen_edges, visited);
            }
        }
    }
    pub fn total_statements(&self) -> usize {
        self.statements_by_issuer.values().map(|v| v.len()).sum()
    }

    /// Get total block count.
    pub fn total_blocks(&self) -> usize {
        self.blocks_by_issuer.values().map(|v| v.len()).sum()
    }
}

/// Application state.
#[derive(Clone)]
pub struct AppState {
    store: Arc<RwLock<TrustStore>>,
    config: RelayConfig,
}

// === API Types ===

#[derive(Debug, Deserialize)]
pub struct StatementsQuery {
    issuer: Option<String>,
    subject: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GraphQuery {
    center: String,
    #[serde(default = "default_depth")]
    depth: usize,
}

fn default_depth() -> usize { 2 }

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_statements: usize,
    pub total_blocks: usize,
    pub unique_issuers: usize,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

// === Handlers ===

/// Health check endpoint.
async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok", "service": "trust-relay"}))
}

/// Get relay statistics.
async fn stats(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.store.read().unwrap();
    Json(StatsResponse {
        total_statements: store.total_statements(),
        total_blocks: store.total_blocks(),
        unique_issuers: store.statement_counts.len(),
    })
}

/// Submit a trust statement.
async fn submit_statement(
    State(state): State<AppState>,
    Json(statement): Json<TrustStatement>,
) -> impl IntoResponse {
    // Verify the statement signature
    if let Err(e) = statement.verify() {
        warn!("Invalid statement signature: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: format!("Invalid signature: {}", e) }),
        ).into_response();
    }

    // Add to store
    let mut store = state.store.write().unwrap();
    match store.add_statement(statement.clone(), state.config.max_statements_per_identity) {
        Ok(()) => {
            info!("Added trust statement: {} -> {}", statement.issuer, statement.subject);
            (StatusCode::CREATED, Json(serde_json::json!({"status": "accepted"}))).into_response()
        }
        Err(e) => {
            warn!("Failed to add statement: {}", e);
            (StatusCode::TOO_MANY_REQUESTS, Json(ErrorResponse { error: e })).into_response()
        }
    }
}

/// Submit a block statement.
async fn submit_block(
    State(state): State<AppState>,
    Json(statement): Json<BlockStatement>,
) -> impl IntoResponse {
    // Verify the statement signature
    if let Err(e) = statement.verify() {
        warn!("Invalid block signature: {}", e);
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: format!("Invalid signature: {}", e) }),
        ).into_response();
    }

    // Add to store
    let mut store = state.store.write().unwrap();
    store.add_block(statement.clone());
    info!("Added block statement: {} -> {}", statement.issuer, statement.subject);
    
    (StatusCode::CREATED, Json(serde_json::json!({"status": "accepted"}))).into_response()
}

/// Query trust statements.
async fn query_statements(
    State(state): State<AppState>,
    Query(query): Query<StatementsQuery>,
) -> impl IntoResponse {
    let store = state.store.read().unwrap();

    let statements: Vec<TrustStatement> = match (&query.issuer, &query.subject) {
        (Some(issuer), Some(subject)) => {
            store.get_statement(issuer, subject)
                .map(|s| vec![s.statement.clone()])
                .unwrap_or_default()
        }
        (Some(issuer), None) => {
            store.get_by_issuer(issuer)
                .into_iter()
                .map(|s| s.statement.clone())
                .collect()
        }
        (None, Some(subject)) => {
            store.get_by_subject(subject)
                .into_iter()
                .map(|s| s.statement.clone())
                .collect()
        }
        (None, None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse { error: "Must specify issuer or subject".to_string() }),
            ).into_response();
        }
    };

    Json(statements).into_response()
}

/// Query blocks for an issuer.
async fn query_blocks(
    State(state): State<AppState>,
    Path(issuer): Path<String>,
) -> impl IntoResponse {
    let store = state.store.read().unwrap();
    let blocks: Vec<BlockStatement> = store
        .get_blocks_by_issuer(&issuer)
        .into_iter()
        .map(|s| s.statement.clone())
        .collect();
    Json(blocks)
}

/// Check if subject is blocked by issuer.
async fn check_blocked(
    State(state): State<AppState>,
    Path((issuer, subject)): Path<(String, String)>,
) -> impl IntoResponse {
    let store = state.store.read().unwrap();
    let blocked = store.is_blocked(&issuer, &subject);
    Json(serde_json::json!({"blocked": blocked}))
}

/// Get trust graph centered on a DID.
async fn get_graph(
    State(state): State<AppState>,
    Query(query): Query<GraphQuery>,
) -> impl IntoResponse {
    let store = state.store.read().unwrap();
    let depth = query.depth.min(5); // Cap depth to prevent expensive queries
    let graph = store.build_graph(&query.center, depth);
    Json(graph)
}

/// Build the router.
fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/stats", get(stats))
        .route("/trust/statements", get(query_statements))
        .route("/trust/statements", post(submit_statement))
        .route("/trust/blocks", post(submit_block))
        .route("/trust/blocks/:issuer", get(query_blocks))
        .route("/trust/blocked/:issuer/:subject", get(check_blocked))
        .route("/trust/graph", get(get_graph))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load config from environment
    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8082".to_string())
        .parse()
        .expect("Invalid LISTEN_ADDR");

    let max_statements: usize = std::env::var("MAX_STATEMENTS_PER_IDENTITY")
        .unwrap_or_else(|_| "1000".to_string())
        .parse()
        .expect("Invalid MAX_STATEMENTS_PER_IDENTITY");

    let config = RelayConfig {
        listen_addr,
        max_statements_per_identity: max_statements,
    };

    info!("Starting Trust Relay on {}", config.listen_addr);

    let state = AppState {
        store: Arc::new(RwLock::new(TrustStore::new())),
        config: config.clone(),
    };

    let app = build_router(state);
    let listener = TcpListener::bind(config.listen_addr).await.unwrap();

    info!("Trust Relay listening on {}", config.listen_addr);
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState {
            store: Arc::new(RwLock::new(TrustStore::new())),
            config: RelayConfig::default(),
        }
    }

    #[tokio::test]
    async fn test_health() {
        let app = build_router(test_state());
        let response = app
            .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_stats_empty() {
        let app = build_router(test_state());
        let response = app
            .oneshot(Request::builder().uri("/stats").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_store_add_statement() {
        let mut store = TrustStore::new();
        let issuer = RootKey::generate();
        let subject = RootKey::generate();

        let statement = TrustStatement::new(issuer.did(), subject.did(), 0.8)
            .sign(&issuer)
            .unwrap();

        store.add_statement(statement.clone(), 100).unwrap();

        assert_eq!(store.total_statements(), 1);
        assert!(store.get_statement(&issuer.did().to_string(), &subject.did().to_string()).is_some());
    }

    #[test]
    fn test_store_rate_limit() {
        let mut store = TrustStore::new();
        let issuer = RootKey::generate();

        for i in 0..5 {
            let subject = RootKey::generate();
            let statement = TrustStatement::new(issuer.did(), subject.did(), 0.5)
                .sign(&issuer)
                .unwrap();
            
            let result = store.add_statement(statement, 5);
            if i < 5 {
                assert!(result.is_ok());
            }
        }

        // 6th should fail
        let subject = RootKey::generate();
        let statement = TrustStatement::new(issuer.did(), subject.did(), 0.5)
            .sign(&issuer)
            .unwrap();
        assert!(store.add_statement(statement, 5).is_err());
    }

    #[test]
    fn test_store_block() {
        let mut store = TrustStore::new();
        let issuer = RootKey::generate();
        let subject = RootKey::generate();

        let block = BlockStatement::new(
            issuer.did(),
            subject.did(),
            "spam",
            BlockSeverity::Permanent,
        )
        .sign(&issuer)
        .unwrap();

        store.add_block(block);

        assert!(store.is_blocked(&issuer.did().to_string(), &subject.did().to_string()));
        assert!(!store.is_blocked(&subject.did().to_string(), &issuer.did().to_string()));
    }

    #[test]
    fn test_build_graph() {
        let mut store = TrustStore::new();
        let agent_a = RootKey::generate();
        let agent_b = RootKey::generate();
        let agent_c = RootKey::generate();

        // A trusts B
        let stmt1 = TrustStatement::new(agent_a.did(), agent_b.did(), 0.9)
            .sign(&agent_a)
            .unwrap();
        store.add_statement(stmt1, 100).unwrap();

        // B trusts C
        let stmt2 = TrustStatement::new(agent_b.did(), agent_c.did(), 0.8)
            .sign(&agent_b)
            .unwrap();
        store.add_statement(stmt2, 100).unwrap();

        // Graph centered on B with depth 2
        let graph = store.build_graph(&agent_b.did().to_string(), 2);

        assert_eq!(graph.nodes.len(), 3); // A, B, C
        assert_eq!(graph.edges.len(), 2);
    }
}
