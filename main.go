package main

import (
	"log"
	"net/http"
	"os"

	"secure-vault/handlers"
	"secure-vault/middleware"
	"secure-vault/storage"
	"secure-vault/utils"

	"github.com/gorilla/mux"
)

func main() {
	// Load master AES key from .env
	if err := utils.LoadAESKey(); err != nil {
		log.Fatalf("Failed to load AES key: %v", err)
	}

	// Init BoltDB storage
	if err := storage.Init(); err != nil {
		log.Fatalf("Failed to init storage: %v", err)
	}

	// Create router
	r := mux.NewRouter()

	
	// Routes
	public := r.PathPrefix("/").Subrouter()
	public.Use(middleware.RateLimit) // optional
	public.HandleFunc("/auth/token", handlers.GetToken).Methods("POST")

	secure := r.PathPrefix("/vault").Subrouter()
	secure.Use(middleware.RateLimit)
	secure.Use(middleware.RequireAuth)
	secure.HandleFunc("/store", handlers.StoreKey).Methods("POST")
	secure.HandleFunc("/retrive/{id}", handlers.GetKey).Methods("GET")
	secure.HandleFunc("/set-mode", handlers.SetCryptoModeHandler).Methods("POST")
	secure.HandleFunc("/get-mode", handlers.GetCryptoModeHandler).Methods("GET")
	secure.HandleFunc("/rotate/{id}", handlers.RotateKeyHandler).Methods("POST")
	// Optional: Healthcheck
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server running on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
