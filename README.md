# 🔐 Secure Vault Backend

A non-custodial, cryptographically secure vault system for storing public keys using classical (ECC) or post-quantum (Kyber) encryption — built with Go, BoltDB, Docker, JWT authentication, and rate-limiting middleware.

---

## 🚀 Project Overview

This project provides:

- 🔐 Secure key storage with envelope encryption
- ♻️ Key rotation endpoint
- 🔓 Basic authenticated access via JWT
- 🔁 Dynamic encryption mode switching (`classical` ↔ `quantum-safe`)
- 🧠 Rate-limited and middleware-secured API

Supported modes:

- **Classical Mode**: secp256k1 + AES-GCM
- **Quantum-Safe Mode**: Kyber + AES-GCM (via liboqs-go)

---

## 🔐 Crypto Layer

The system uses **envelope encryption** to securely store public keys. Two modes are supported:

### 🟦 Classical Mode – `secp256k1` + AES-GCM

1. **Ephemeral ECC Key Generation**: A new ephemeral `secp256k1` keypair is generated per request.
2. **AES Key Derivation**: The ephemeral private key is hashed using SHA-256 to create a 256-bit AES key.
3. **Encrypt Submitted Key**: The submitted public key is encrypted using AES-GCM and a random nonce.
4. **Encrypt Ephemeral Private Key**: The ephemeral private key is encrypted using AES-GCM with a **persistent AES master key**.
5. **Stored Fields**: `ciphertext`, `nonce`, `ephemeral_pub_key`, `encrypted_ephemeral_priv_key`, `ephemeral_priv_nonce`

### 🟪 Quantum-Safe Mode – Kyber + AES-GCM

1. **Ephemeral Kyber Keypair**: The system generates an ephemeral Kyber keypair using the liboqs-go library for quantum-safe.
2. **Key Encapsulation**: Kyber generates a shared secret and a `kem_ciphertext`.
3. **AES Key Derivation**: The shared secret is used as the AES key for AES-GCM encryption.
4. **Encrypt Submitted Key**: The submitted key is encrypted with AES-GCM using the derived AES key.
5. **Encrypt Kyber Private Key**: The Kyber private key is encrypted using AES-GCM with the server's AES master key.
6. **Stored Fields**: `ciphertext`, `nonce`, `kyber_ciphertext`, `kyber_pub_key`, `encrypted_kyber_priv_key`, `kyber_priv_nonce`

## Features Completed

| Feature                                   | Status |
| ----------------------------------------- | ------ |
| JWT Auth (`/auth/token`)                  | ✅     |
| Store key (`/vault/store`)                | ✅     |
| Rotate key (`/vault/rotate/{id}`)         | ✅     |
| Retrieve key (`/vault/retrive/{id}`)      | ✅     |
| Switch crypto mode (`/vault/set-mode`)    | ✅     |
| Get current mode (`/vault/get-mode`)      | ✅     |
| Rate limit via middleware                 | ✅     |
| Ephemeral ECC + Kyber envelope encryption | ✅     |
| BoltDB persistent storage                 | ✅     |

---

# 🔐 Secure Vault Backend

A non-custodial, cryptographically secure vault system for storing public keys using classical (ECC) or post-quantum (Kyber) encryption — built with Go, BoltDB, Docker, JWT authentication, and rate-limiting middleware.

---

## 🚀 Project Overview

This project provides:

- 🔐 Secure key storage with envelope encryption
- ♻️ Key rotation endpoint
- 🔓 Authenticated access via JWT
- 🔁 Dynamic encryption mode switching (`classical` ↔ `quantum-safe`)
- 🧠 Rate-limited and middleware-secured API

Supported modes:

- **Classical Mode**: secp256k1 + AES-GCM
- **Quantum-Safe Mode**: Kyber + AES-GCM (via liboqs-go)

## ⚙️ Setup Guide

### 1. Clone & Configure

git clone https://github.com/DarkHorse0725/marvelx-test.git
cd marvelx-test

## Create a .env file:

VAULT_DB=secure-vault.db
PRIVATE_KEY_AES=your-256bit-hex-key
JWT_SECRET=your_jwt_secret_here

### 2. Run with Docker

docker-compose up --build

## 🧪 Testing the API

### 1. Get a JWT

curl -X POST http://localhost:8080/auth/token \
 -H "Content-Type: application/json" \
 -d '{"user_id":"alice"}'

### 2. Use the JWT

curl -H "Authorization: Bearer <token>" ...

### 3. Store a Key

curl -X POST http://localhost:8080/vault/store \
 -H "Authorization: Bearer <token>" \
 -H "Content-Type: application/json" \
 -d '{
"key": "base64_or_hex_encoded",
"key_type": "secp256k1" or "kyber512",
"key_encoding": "string" or "hex",
"label": "my-key",
}'

### 4 Rotate a key

curl -X POST http://localhost:8080/vault/rotate/abc123 \
 -H "Authorization: Bearer <your_token>" \
 -H "Content-Type: application/json" \
 -d '{
"key": "NEW_BASE64_PUBKEY",
"key_type": "secp256k1",
"key_encoding": "string",
"label": "My Login Key (Updated)"
}'

### 5 Retrieve a key

curl -X GET http://localhost:8080/vault/retrive/abc123 \
 -H "Authorization: Bearer <your_token>"

### 6. Get Current Crypto Mode

curl -X GET http://localhost:8080/vault/get-mode \
 -H "Authorization: Bearer <your_token>"

### 7. Set Crypto Mode

curl -X POST http://localhost:8080/vault/set-mode \
 -H "Authorization: Bearer <your_token>" \
 -H "Content-Type: application/json" \
 -d '{"mode": "quantum-safe"}'

#### Comment on future improvements: how would you extend this to a multi-user vault?

- Log in and get their own token
- Save and manage only their keys
- Not see or touch other people’s data

# Already done

- Each person gets a token (JWT) when they log in
- That token includes their user_id
- Every stored key is labeled with that user_id
- So the system already knows who owns what

1. Always check who owns the Key.
   When someone tries to view or update a key, we check if it's his. If not, access denied.
2. Let users see only their own keys
   Add a new endpoint:
   GET /vault/list
   This will return only the keys that belong to the logged-in user.
3. Every time someone saves or rotates a key, we can log
   Currently, basic implementation has been done.

########################################################################################
