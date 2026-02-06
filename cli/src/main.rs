//! AIP CLI - Agent Identity Protocol command-line tool.

use aip_core::{Did, DidDocument, RootKey};
use aip_handshake::{
    messages::{Hello, Proof, ProofAccepted},
    protocol::{sign_proof, verify_counter_proof, Verifier},
};
use anyhow::{Context, Result};
use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Agent Identity Protocol CLI
#[derive(Parser)]
#[command(name = "aip")]
#[command(about = "Agent Identity Protocol - verifiable agent identity", long_about = None)]
struct Cli {
    /// Path to identity file (default: ~/.aip/identity.json)
    #[arg(short, long, global = true)]
    identity: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Identity management
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// DID Document management
    Document {
        #[command(subcommand)]
        action: DocumentAction,
    },
    /// Resolve a DID
    Resolve {
        /// The DID to resolve
        did: String,
        /// Resolver URL
        #[arg(short, long, default_value = "http://localhost:8500")]
        resolver: String,
    },
    /// Handshake operations
    Handshake {
        #[command(subcommand)]
        action: HandshakeAction,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new identity
    Generate {
        /// Force overwrite existing identity
        #[arg(short, long)]
        force: bool,
    },
    /// Show current identity
    Show,
    /// Export public identity (safe to share)
    Export,
}

#[derive(Subcommand)]
enum DocumentAction {
    /// Create and sign a DID Document
    Create {
        /// Handshake endpoint URL
        #[arg(short = 'e', long)]
        endpoint: Option<String>,
    },
    /// Publish document to a resolver
    Publish {
        /// Resolver URL
        #[arg(short, long, default_value = "http://localhost:8500")]
        resolver: String,
        /// Handshake endpoint URL
        #[arg(short = 'e', long)]
        endpoint: Option<String>,
    },
}

#[derive(Subcommand)]
enum HandshakeAction {
    /// Simulate a local handshake between two identities
    Test,
    /// Start handshake server
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "8400")]
        port: u16,
    },
    /// Connect to a remote agent and perform handshake
    Connect {
        /// URL of the remote agent (e.g., http://localhost:8400)
        url: String,
    },
}

/// Stored identity file format.
#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    did: String,
    #[serde(with = "hex_bytes")]
    secret_key: [u8; 32],
    created_at: String,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid key length"))
    }
}

fn get_identity_path(cli_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = cli_path {
        return Ok(path);
    }

    let proj_dirs = directories::ProjectDirs::from("ai", "aip", "aip")
        .context("Could not determine config directory")?;

    let config_dir = proj_dirs.config_dir();
    std::fs::create_dir_all(config_dir)?;

    Ok(config_dir.join("identity.json"))
}

fn load_identity(path: &PathBuf) -> Result<(RootKey, Did)> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Could not read identity file: {}", path.display()))?;

    let stored: StoredIdentity =
        serde_json::from_str(&contents).context("Invalid identity file format")?;

    let root_key = RootKey::from_bytes(&stored.secret_key)?;
    let did = root_key.did();

    if did.to_string() != stored.did {
        anyhow::bail!("Identity file corrupted: DID mismatch");
    }

    Ok((root_key, did))
}

fn save_identity(path: &PathBuf, root_key: &RootKey) -> Result<()> {
    let stored = StoredIdentity {
        did: root_key.did().to_string(),
        secret_key: root_key.to_bytes(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let contents = serde_json::to_string_pretty(&stored)?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, contents)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

// ============================================================================
// Identity Commands
// ============================================================================

fn cmd_identity_generate(path: PathBuf, force: bool) -> Result<()> {
    if path.exists() && !force {
        anyhow::bail!(
            "Identity already exists at {}. Use --force to overwrite.",
            path.display()
        );
    }

    let root_key = RootKey::generate();
    let did = root_key.did();

    save_identity(&path, &root_key)?;

    println!("Generated new identity:");
    println!("  DID: {}", did);
    println!("  Saved to: {}", path.display());

    Ok(())
}

fn cmd_identity_show(path: PathBuf) -> Result<()> {
    let (_, did) = load_identity(&path)?;

    println!("Identity:");
    println!("  DID: {}", did);
    println!("  Key ID: {}", did.key_id());
    println!("  File: {}", path.display());

    Ok(())
}

fn cmd_identity_export(path: PathBuf) -> Result<()> {
    let (_, did) = load_identity(&path)?;

    let export = serde_json::json!({
        "did": did.to_string(),
        "publicKey": did.key_id(),
    });

    println!("{}", serde_json::to_string_pretty(&export)?);

    Ok(())
}

// ============================================================================
// Document Commands
// ============================================================================

fn cmd_document_create(path: PathBuf, endpoint: Option<String>) -> Result<()> {
    let (key, _) = load_identity(&path)?;

    let mut doc = DidDocument::new(&key);

    if let Some(ep) = endpoint {
        doc = doc.with_handshake_endpoint(&ep);
    }

    let doc = doc.sign(&key)?;

    println!("{}", serde_json::to_string_pretty(&doc)?);

    Ok(())
}

async fn cmd_document_publish(
    path: PathBuf,
    resolver: String,
    endpoint: Option<String>,
) -> Result<()> {
    let (key, did) = load_identity(&path)?;

    let mut doc = DidDocument::new(&key);

    if let Some(ep) = endpoint {
        doc = doc.with_handshake_endpoint(&ep);
    }

    let doc = doc.sign(&key)?;

    println!("Publishing DID Document...");
    println!("  DID: {}", did);
    println!("  Resolver: {}", resolver);

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/documents", resolver))
        .json(&doc)
        .send()
        .await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        println!();
        println!("✓ Document published!");
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let error = response.text().await?;
        anyhow::bail!("Failed to publish: {}", error);
    }

    Ok(())
}

// ============================================================================
// Resolve Command
// ============================================================================

async fn cmd_resolve(did: String, resolver: String) -> Result<()> {
    println!("Resolving {}...", did);

    let client = reqwest::Client::new();
    let encoded_did = urlencoding::encode(&did);
    let response = client
        .get(format!("{}/documents/{}", resolver, encoded_did))
        .send()
        .await?;

    if response.status().is_success() {
        let doc: DidDocument = response.json().await?;

        // Verify the document
        doc.verify()?;
        println!("✓ Document signature verified");
        println!();
        println!("{}", serde_json::to_string_pretty(&doc)?);
    } else if response.status() == StatusCode::NOT_FOUND {
        anyhow::bail!("DID not found in resolver");
    } else {
        let error = response.text().await?;
        anyhow::bail!("Failed to resolve: {}", error);
    }

    Ok(())
}

// ============================================================================
// Handshake Commands
// ============================================================================

fn cmd_handshake_test(path: PathBuf) -> Result<()> {
    let (my_key, my_did) = load_identity(&path)?;
    let peer_key = RootKey::generate();
    let peer_did = peer_key.did();

    println!("Testing handshake...");
    println!("  Our DID: {}", my_did);
    println!("  Peer DID: {}", peer_did);
    println!();

    let hello = Hello::new(my_did.to_string());
    println!("1. Sent Hello");

    let verifier = Verifier::new(peer_did.clone());
    let challenge = verifier.handle_hello(&hello)?;
    println!(
        "2. Received Challenge (nonce: {}...)",
        &challenge.nonce[..16]
    );

    let proof = sign_proof(&challenge, &my_did, &my_key, Some(peer_did.to_string()))?;
    println!("3. Sent Proof (sig: {}...)", &proof.signature[..16]);

    verifier.verify_proof(&proof, &challenge)?;
    let accepted = verifier.accept_proof(&proof, &peer_key)?;
    println!(
        "4. Received ProofAccepted (session: {})",
        accepted.session_id
    );

    verify_counter_proof(
        &accepted.counter_proof,
        proof.counter_challenge.as_ref().unwrap(),
    )?;
    println!("5. Verified counter-proof");

    println!();
    println!("✓ Handshake successful!");

    Ok(())
}

// ============================================================================
// HTTP Server
// ============================================================================

#[allow(dead_code)]
struct ServerState {
    key: RootKey,
    did: Did,
    verifier: Verifier,
    pending_challenges: Mutex<std::collections::HashMap<String, aip_handshake::Challenge>>,
}

async fn handle_hello(
    State(state): State<Arc<ServerState>>,
    Json(hello): Json<Hello>,
) -> Result<Json<aip_handshake::Challenge>, (StatusCode, String)> {
    println!("← Received Hello from {}", hello.did);

    let challenge = state
        .verifier
        .handle_hello(&hello)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let challenge_hash = aip_handshake::protocol::hash_challenge(&challenge)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state
        .pending_challenges
        .lock()
        .await
        .insert(challenge_hash, challenge.clone());

    println!("→ Sent Challenge");

    Ok(Json(challenge))
}

async fn handle_proof(
    State(state): State<Arc<ServerState>>,
    Json(proof): Json<Proof>,
) -> Result<Json<ProofAccepted>, (StatusCode, String)> {
    println!("← Received Proof from {}", proof.responder_did);

    let challenge = state
        .pending_challenges
        .lock()
        .await
        .remove(&proof.challenge_hash)
        .ok_or((StatusCode::BAD_REQUEST, "Unknown challenge".to_string()))?;

    state
        .verifier
        .verify_proof(&proof, &challenge)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    println!("  ✓ Proof verified");

    let accepted = state
        .verifier
        .accept_proof(&proof, &state.key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    println!("→ Sent ProofAccepted (session: {})", accepted.session_id);

    Ok(Json(accepted))
}

async fn cmd_handshake_serve(path: PathBuf, port: u16) -> Result<()> {
    let (key, did) = load_identity(&path)?;

    println!("Starting handshake server...");
    println!("  DID: {}", did);
    println!("  Listening on: http://0.0.0.0:{}", port);
    println!();

    let state = Arc::new(ServerState {
        verifier: Verifier::new(did.clone()),
        key,
        did,
        pending_challenges: Mutex::new(std::collections::HashMap::new()),
    });

    let app = Router::new()
        .route("/hello", post(handle_hello))
        .route("/proof", post(handle_proof))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    println!("Server ready. Waiting for connections...");
    println!();

    axum::serve(listener, app).await?;

    Ok(())
}

// ============================================================================
// HTTP Client
// ============================================================================

async fn cmd_handshake_connect(path: PathBuf, url: String) -> Result<()> {
    let (my_key, my_did) = load_identity(&path)?;

    println!("Connecting to {}...", url);
    println!("  Our DID: {}", my_did);
    println!();

    let client = reqwest::Client::new();

    let hello = Hello::new(my_did.to_string());
    println!("1. Sending Hello...");

    let challenge: aip_handshake::Challenge = client
        .post(format!("{}/hello", url))
        .json(&hello)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!("2. Received Challenge from {}", challenge.issuer);

    let proof = sign_proof(&challenge, &my_did, &my_key, Some(challenge.issuer.clone()))?;
    println!("3. Sending Proof...");

    let accepted: ProofAccepted = client
        .post(format!("{}/proof", url))
        .json(&proof)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!(
        "4. Received ProofAccepted (session: {})",
        accepted.session_id
    );

    verify_counter_proof(
        &accepted.counter_proof,
        proof.counter_challenge.as_ref().unwrap(),
    )?;
    println!("5. Verified counter-proof");

    println!();
    println!("✓ Handshake successful with {}!", challenge.issuer);

    Ok(())
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let identity_path = get_identity_path(cli.identity)?;

    match cli.command {
        Commands::Identity { action } => match action {
            IdentityAction::Generate { force } => cmd_identity_generate(identity_path, force),
            IdentityAction::Show => cmd_identity_show(identity_path),
            IdentityAction::Export => cmd_identity_export(identity_path),
        },
        Commands::Document { action } => match action {
            DocumentAction::Create { endpoint } => cmd_document_create(identity_path, endpoint),
            DocumentAction::Publish { resolver, endpoint } => {
                cmd_document_publish(identity_path, resolver, endpoint).await
            }
        },
        Commands::Resolve { did, resolver } => cmd_resolve(did, resolver).await,
        Commands::Handshake { action } => match action {
            HandshakeAction::Test => cmd_handshake_test(identity_path),
            HandshakeAction::Serve { port } => cmd_handshake_serve(identity_path, port).await,
            HandshakeAction::Connect { url } => cmd_handshake_connect(identity_path, url).await,
        },
    }
}
