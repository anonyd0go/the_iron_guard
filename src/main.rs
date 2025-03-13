use clap::{Parser, Subcommand};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use ring::{aead, rand, pbkdf2};
use ring::rand::SecureRandom;
use argon2;
use rpassword::read_password;
use base64;
use std::num::NonZeroU32;

#[derive(Parser)]
#[clap(name = "Password Manager")]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Add { service: String, password: String },
    Get { service: String },
}

#[derive(Serialize, Deserialize)]
struct PasswordStore {
    passwords: HashMap<String, String>, // service: base64-encoded encrypted password
}

// Hash the master password using Argon2
fn hash_password(password: &str) -> String {
    let salt = b"randomsalt123456"; // Should be unique per user in a real app
    let config = argon2::Argon2::default();
    argon2::hash_encoded(password.as_bytes(), salt, &config).unwrap()
}

// Verify the master password
fn verify_password(hash: &str, password: &str) -> bool {
    argon2::verify_encoded(hash, password.as_bytes()).unwrap_or(false)
}

// Encrypt a password
fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut nonce = vec![0; 12];
    rand::SystemRandom::new().fill(&mut nonce).unwrap();
    let mut in_out = data.to_vec();
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key).unwrap()
    );
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce.clone()),
        aead::Aad::empty(),
        &mut in_out
    ).unwrap();
    [nonce, in_out].concat()
}

// Decrypt a password
fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, &'static str> {
    if data.len() < 12 { return Err("Invalid encrypted data"); }
    let (nonce, cipher) = data.split_at(12);
    let mut in_out = cipher.to_vec();
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key).unwrap()
    );
    key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce.to_vec()),
        aead::Aad::empty(),
        &mut in_out
    ).map_err(|_| "Decryption failed")?;
    Ok(in_out)
}

// Save the password store to a file
fn save_store(store: &PasswordStore, path: &str) -> Result<(), std::io::Error> {
    let data = serde_json::to_string(store)?;
    fs::write(path, data)?;
    Ok(())
}

// Load the password store from a file
fn load_store(path: &str) -> Result<PasswordStore, Box<dyn std::error::Error>> {
    let data = fs::read_to_string(path)?;
    let store = serde_json::from_str(&data)?;
    Ok(store)
}

fn main() {
    let cli = Cli::parse();

    // Master password handling
    let master_hash_path = "master.hash";
    let master_hash = match fs::read_to_string(master_hash_path) {
        Ok(hash) => hash,
        Err(_) => {
            println!("Set a master password:");
            let master = read_password().unwrap();
            let hash = hash_password(&master);
            fs::write(master_hash_path, &hash).unwrap();
            hash
        }
    };

    // Authenticate
    println!("Enter your master password:");
    let input_master = read_password().unwrap();
    if !verify_password(&master_hash, &input_master) {
        println!("Authentication failed!");
        return;
    }

    // Derive encryption key from master password
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac_sha256(input_master.as_bytes(), b"salt", 10000, &mut key);

    // Load or create password store
    let store_path = "passwords.json";
    let mut store = load_store(store_path).unwrap_or(PasswordStore {
        passwords: HashMap::new()
    });

    // Handle commands
    match cli.command {
        Commands::Add { service, password } => {
            let encrypted = encrypt(password.as_bytes(), &key);
            let encoded = base64::encode(&encrypted);
            store.passwords.insert(service, encoded);
            save_store(&store, store_path).unwrap();
            println!("Password added!");
        }
        Commands::Get { service } => {
            if let Some(encoded) = store.passwords.get(&service) {
                let encrypted = base64::decode(encoded).unwrap();
                match decrypt(&encrypted, &key) {
                    Ok(decrypted) => {
                        let password = String::from_utf8(decrypted).unwrap();
                        println!("Password for {}: {}", service, password);
                    }
                    Err(e) => println!("Error: {}", e),
                }
            } else {
                println!("Service not found!");
            }
        }
    }
}
