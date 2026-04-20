package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
)

// =====================================
// KONFIGURASI
// =====================================

// Ganti dengan Google Client ID kamu dari Google Cloud Console
const defaultClientID = "Y258648454436-sdv5da3pj4uasq3j7d8hjant44gtui5g.apps.googleusercontent.com"

func getClientID() string {
	if id := os.Getenv("GOOGLE_CLIENT_ID"); id != "" {
		return id
	}
	return defaultClientID
}

// =====================================
// STRUCT
// =====================================

// GoogleTokenInfo - response dari Google tokeninfo endpoint
type GoogleTokenInfo struct {
	Email            string `json:"email"`
	EmailVerified    string `json:"email_verified"`
	Name             string `json:"name"`
	Picture          string `json:"picture"`
	GivenName        string `json:"given_name"`
	FamilyName       string `json:"family_name"`
	Aud              string `json:"aud"`
	Sub              string `json:"sub"`
	Iss              string `json:"iss"`
	Exp              string `json:"exp"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// UserProfile - data profil yang dikirim balik ke frontend
type UserProfile struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Picture string `json:"picture"`
}

// TokenRequest - body request dari frontend
type TokenRequest struct {
	Credential string `json:"credential"`
}

// Response - format response API
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// =====================================
// VERIFIKASI TOKEN GOOGLE
// =====================================

func verifyGoogleToken(credential string) (*UserProfile, error) {
	url := "https://oauth2.googleapis.com/tokeninfo?id_token=" + credential
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("gagal menghubungi Google: %w", err)
	}
	defer resp.Body.Close()

	var tokenInfo GoogleTokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&tokenInfo); err != nil {
		return nil, fmt.Errorf("gagal decode response Google: %w", err)
	}

	if tokenInfo.Error != "" {
		return nil, fmt.Errorf("token tidak valid: %s", tokenInfo.ErrorDescription)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token ditolak Google (status: %d)", resp.StatusCode)
	}

	if tokenInfo.Aud != getClientID() {
		return nil, fmt.Errorf("audience tidak valid: token bukan untuk aplikasi ini")
	}

	if tokenInfo.Iss != "accounts.google.com" && tokenInfo.Iss != "https://accounts.google.com" {
		return nil, fmt.Errorf("issuer tidak valid: %s", tokenInfo.Iss)
	}

	return &UserProfile{
		Name:    tokenInfo.Name,
		Email:   tokenInfo.Email,
		Picture: tokenInfo.Picture,
	}, nil
}

// =====================================
// HANDLER HTTP
// =====================================

func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

func googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(Response{Success: false, Message: "Method tidak diizinkan"})
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Success: false, Message: "Format request tidak valid"})
		return
	}

	if req.Credential == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{Success: false, Message: "Credential tidak boleh kosong"})
		return
	}

	profile, err := verifyGoogleToken(req.Credential)
	if err != nil {
		log.Printf("[ERROR] Verifikasi token gagal: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Response{Success: false, Message: "Token tidak valid atau sudah expired"})
		return
	}

	log.Printf("[INFO] Login berhasil: %s (%s)", profile.Name, profile.Email)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Login berhasil",
		Data:    profile,
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "index.html")
}

// =====================================
// MAIN
// =====================================

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/api/google-callback", googleCallbackHandler)

	log.Printf("[INFO] Server berjalan di http://localhost:%s", port)
	log.Printf("[INFO] Client ID: %s", getClientID())

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("[FATAL] Server gagal berjalan: %v", err)
	}
}