module secure-vault

go 1.24.4

require (
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/open-quantum-safe/liboqs-go v0.0.0-20250119172907-28b5301df438
	go.etcd.io/bbolt v1.4.1
	golang.org/x/time v0.12.0
)

require golang.org/x/sys v0.29.0 // indirect
