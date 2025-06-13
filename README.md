
# Secure Vault API

A cryptographic vault backend supporting classical and post-quantum key storage with secure JWT-authentication.

## Features
- RESTful API
- JWT-protected endpoints
- ECC (secp256k1) and Kyber encryption modes
- AES-GCM at-rest encryption
- Persistent key storage via BoltDB
- Non-custodial: server never sees private keys

## Endpoints
- POST /vault/store — Store a client public key
- GET /vault/{id} — Retrieve stored key info
- POST /vault/rotate/{id} — Rotate the stored public key
- POST /vault/set-mode — Switch between classical and quantum-safe mode

## Setup

```bash
docker-compose up --build
```

## Authentication

Use JWT signed with secret from `.env`:
```
Authorization: Bearer <your_token>
```
