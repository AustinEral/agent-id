//! AIP CLI - Agent Identity Protocol command-line tool.

use aip_core::{Did, RootKey};
use aip_handshake::{
    messages::Hello,
    protocol::{Verifier, sign_proof},
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    /// Handshake testing
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
enum HandshakeAction {
    /// Simulate a local handshake between two identities
    Test,
    /// Act as handshake server (listen for connections)
    Serve {
        /// Port to listen on
        #[arg(short, long, default_value = "8400")]
        port: u16,
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

    // Verify DID matches
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

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, contents)?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

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

    // Export only public information
    let export = serde_json::json!({
        "did": did.to_string(),
        "publicKey": did.key_id(),
    });

    println!("{}", serde_json::to_string_pretty(&export)?);

    Ok(())
}

fn cmd_handshake_test(path: PathBuf) -> Result<()> {
    // Load our identity
    let (my_key, my_did) = load_identity(&path)?;

    // Create a temporary peer for testing
    let peer_key = RootKey::generate();
    let peer_did = peer_key.did();

    println!("Testing handshake...");
    println!("  Our DID: {}", my_did);
    println!("  Peer DID: {}", peer_did);
    println!();

    // Step 1: We send Hello
    let hello = Hello::new(my_did.to_string());
    println!("1. Sent Hello");

    // Step 2: Peer sends Challenge
    let verifier = Verifier::new(peer_did.clone());
    let challenge = verifier.handle_hello(&hello)?;
    println!(
        "2. Received Challenge (nonce: {}...)",
        &challenge.nonce[..16]
    );

    // Step 3: We send Proof
    let proof = sign_proof(&challenge, &my_did, &my_key, Some(peer_did.to_string()))?;
    println!("3. Sent Proof (sig: {}...)", &proof.signature[..16]);

    // Step 4: Peer verifies and accepts
    verifier.verify_proof(&proof, &challenge)?;
    let accepted = verifier.accept_proof(&proof, &peer_key)?;
    println!(
        "4. Received ProofAccepted (session: {})",
        accepted.session_id
    );

    // Step 5: We verify counter-proof
    aip_handshake::verify_counter_proof(
        &accepted.counter_proof,
        proof.counter_challenge.as_ref().unwrap(),
    )?;
    println!("5. Verified counter-proof");

    println!();
    println!("✓ Handshake successful!");

    Ok(())
}

fn cmd_handshake_serve(_path: PathBuf, port: u16) -> Result<()> {
    println!("Handshake server not yet implemented.");
    println!("Would listen on port {}", port);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let identity_path = get_identity_path(cli.identity)?;

    match cli.command {
        Commands::Identity { action } => match action {
            IdentityAction::Generate { force } => cmd_identity_generate(identity_path, force),
            IdentityAction::Show => cmd_identity_show(identity_path),
            IdentityAction::Export => cmd_identity_export(identity_path),
        },
        Commands::Handshake { action } => match action {
            HandshakeAction::Test => cmd_handshake_test(identity_path),
            HandshakeAction::Serve { port } => cmd_handshake_serve(identity_path, port),
        },
    }
}
