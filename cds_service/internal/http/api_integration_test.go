/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"cds/internal/adapters/postgres"
	"cds/internal/config"
	"cds/internal/services"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

const (
	testSerial   = "b4:6a:d4:45:f0:19"
	testEndpoint = "openwifi3.routerarchitects.com"
)

func mustOpenTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set; skipping integration tests")
	}
	if err := requireSafeTestDB(dsn); err != nil {
		t.Fatalf("unsafe POSTGRES_DSN for integration test: %v", err)
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatalf("ping postgres: %v", err)
	}
	return db
}

func requireSafeTestDB(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil {
		return fmt.Errorf("invalid DSN: %w", err)
	}
	dbName := strings.TrimPrefix(path.Clean(u.Path), "/")
	if dbName != "cds_test" {
		return fmt.Errorf("database %q is not allowed; expected %q", dbName, "cds_test")
	}
	return nil
}

func resetDevicesTable(t *testing.T, db *sql.DB) {
	t.Helper()
	const schema = `
CREATE TABLE IF NOT EXISTS public.devices (
  serial TEXT PRIMARY KEY,
  controller_endpoint TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  owner_scope TEXT
);
TRUNCATE TABLE public.devices;
`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("prepare devices table: %v", err)
	}
}

type keyMaterial struct {
	key *rsa.PrivateKey
	kid string
}

func newJWKSHandler(km *keyMaterial) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pub := km.key.Public().(*rsa.PublicKey)
		jwks := map[string]any{
			"keys": []map[string]any{
				{
					"kty": "RSA",
					"kid": km.kid,
					"use": "sig",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	})
}

func newIntegrationRouter(t *testing.T) (http.Handler, *sql.DB, *keyMaterial, *rsa.PrivateKey) {
	t.Helper()
	db := mustOpenTestDB(t)
	resetDevicesTable(t, db)

	tokenKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate token key: %v", err)
	}
	dpopKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate dpop key: %v", err)
	}
	km := &keyMaterial{key: tokenKey, kid: "test-kid-1"}
	jwks := httptest.NewServer(newJWKSHandler(km))

	repo := postgres.NewRepo(db)
	svc := services.New(repo)
	cfg := &config.Config{
		PostgresDSN:            "postgres://unused",
		HTTPAddr:               ":8080",
		AuthMode:               "keycloak-dpop",
		KeycloakIssuerURL:      "https://keycloak.example.com/realms/cds",
		KeycloakJWKSURL:        jwks.URL,
		KeycloakAudience:       "cds-service",
		KeycloakRequiredRole:   "cds-admin",
		KeycloakAdminUIClient:  "cds-admin-ui",
		DPoPRequired:           true,
		DPoPJtiCacheTTLSeconds: 300,
		DPoPProofMaxAgeSeconds: 300,
		DPoPClockSkewSeconds:   30,
		JWKSCacheTTLSeconds:    300,
		TrustedProxyCIDRs:      []string{"10.0.0.0/8", "127.0.0.1/32"},
	}
	t.Cleanup(jwks.Close)
	t.Cleanup(func() { _ = db.Close() })
	return NewRouterWithConfig(cfg, svc), db, km, dpopKey
}

func performJSONRequest(router http.Handler, method, p, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, p, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func signJWT(privateKey *rsa.PrivateKey, header map[string]any, payload map[string]any) string {
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	unsigned := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	h := sha256.Sum256([]byte(unsigned))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwkThumbprintRSA(pub *rsa.PublicKey) string {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	canonical := `{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func buildAdminHeadersForSubject(method, path string, tokenSigner *keyMaterial, dpopKey *rsa.PrivateKey, subject string) map[string]string {
	now := time.Now().Unix()
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	dpopPub := dpopKey.Public().(*rsa.PublicKey)
	dpopJKT := jwkThumbprintRSA(dpopPub)
	accessToken := signJWT(tokenSigner.key, map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": tokenSigner.kid,
	}, map[string]any{
		"iss": "https://keycloak.example.com/realms/cds",
		"sub": subject,
		"aud": []string{"cds-service"},
		"exp": now + 3600,
		"iat": now,
		"azp": "cds-admin-ui",
		"cnf": map[string]any{"jkt": dpopJKT},
		"resource_access": map[string]any{
			"cds-service": map[string]any{
				"roles": []string{"cds-admin"},
			},
		},
	})

	athHash := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(athHash[:])
	dpopProof := signJWT(dpopKey, map[string]any{
		"alg": "RS256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(dpopPub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(dpopPub.E)).Bytes()),
		},
	}, map[string]any{
		"htu": "http://example.com" + path,
		"htm": method,
		"iat": now,
		"jti": fmt.Sprintf("jti-%d-%s-%s-%s", now, method, path, base64.RawURLEncoding.EncodeToString(nonce)),
		"ath": ath,
	})
	return map[string]string{
		"Authorization": "DPoP " + accessToken,
		"DPoP":          dpopProof,
		"Content-Type":  "application/json",
		"Accept":        "application/json",
	}
}

func buildAdminHeaders(method, path string, tokenSigner *keyMaterial, dpopKey *rsa.PrivateKey) map[string]string {
	return buildAdminHeadersForSubject(method, path, tokenSigner, dpopKey, "admin-subject-1")
}

func TestCRUDAndDeviceFacingAPIIntegration(t *testing.T) {
	router, _, signer, dpopKey := newIntegrationRouter(t)

	postBody := `{"serial":"B4:6A:D4:45:F0:19","controller_endpoint":"` + testEndpoint + `"}`
	rr := performJSONRequest(router, http.MethodPost, "/v1/device", postBody, buildAdminHeaders(http.MethodPost, "/v1/device", signer, dpopKey))
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /v1/device got %d, want %d (body=%s)", rr.Code, http.StatusCreated, rr.Body.String())
	}

	rr = performJSONRequest(router, http.MethodGet, "/v1/device", "", buildAdminHeaders(http.MethodGet, "/v1/device", signer, dpopKey))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/device got %d, want %d (body=%s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	var listed []map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listed) != 1 || listed[0]["serial"] != testSerial || listed[0]["controller_endpoint"] != testEndpoint {
		t.Fatalf("unexpected list response: %#v", listed)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/devices/B4:6A:D4:45:F0:19", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-SSL-Client-Verify", "SUCCESS")
	req.Header.Set("Accept", "application/json")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/devices/{serial} got %d, want %d (body=%s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	var device map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&device); err != nil {
		t.Fatalf("decode device response: %v", err)
	}
	if device["serial"] != testSerial || device["controller_endpoint"] != testEndpoint {
		t.Fatalf("unexpected device response: %#v", device)
	}

	putBody := `{"serial":"B4:6A:D4:45:F0:19","controller_endpoint":"openwifi9.routerarchitects.com"}`
	rr = performJSONRequest(router, http.MethodPut, "/v1/device", putBody, buildAdminHeaders(http.MethodPut, "/v1/device", signer, dpopKey))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("PUT /v1/device got %d, want %d (body=%s)", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	rr = performJSONRequest(router, http.MethodDelete, "/v1/device/B4:6A:D4:45:F0:19", "", buildAdminHeaders(http.MethodDelete, "/v1/device/B4:6A:D4:45:F0:19", signer, dpopKey))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE /v1/device/{serial} got %d, want %d (body=%s)", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	rr = performJSONRequest(router, http.MethodGet, "/v1/device", "", buildAdminHeaders(http.MethodGet, "/v1/device", signer, dpopKey))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/device (after delete) got %d, want %d (body=%s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	listed = nil
	if err := json.NewDecoder(rr.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list response after delete: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("expected empty list after delete, got %#v", listed)
	}
}

func TestPostOwnershipConflictPreventsTakeover(t *testing.T) {
	router, db, signer, dpopKey := newIntegrationRouter(t)
	adminA := "admin-subject-a"
	adminB := "admin-subject-b"

	postA1 := `{"serial":"B4:6A:D4:45:F0:19","controller_endpoint":"openwifi-a.routerarchitects.com"}`
	rr := performJSONRequest(router, http.MethodPost, "/v1/device", postA1, buildAdminHeadersForSubject(http.MethodPost, "/v1/device", signer, dpopKey, adminA))
	if rr.Code != http.StatusCreated {
		t.Fatalf("admin A first POST got %d, want %d (body=%s)", rr.Code, http.StatusCreated, rr.Body.String())
	}

	postA2 := `{"serial":"B4:6A:D4:45:F0:19","controller_endpoint":"openwifi-a2.routerarchitects.com"}`
	rr = performJSONRequest(router, http.MethodPost, "/v1/device", postA2, buildAdminHeadersForSubject(http.MethodPost, "/v1/device", signer, dpopKey, adminA))
	if rr.Code != http.StatusCreated {
		t.Fatalf("admin A second POST got %d, want %d (body=%s)", rr.Code, http.StatusCreated, rr.Body.String())
	}

	postB := `{"serial":"B4:6A:D4:45:F0:19","controller_endpoint":"openwifi-b.routerarchitects.com"}`
	rr = performJSONRequest(router, http.MethodPost, "/v1/device", postB, buildAdminHeadersForSubject(http.MethodPost, "/v1/device", signer, dpopKey, adminB))
	if rr.Code != http.StatusConflict {
		t.Fatalf("admin B POST got %d, want %d (body=%s)", rr.Code, http.StatusConflict, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "device already exists for another owner") {
		t.Fatalf("admin B POST body=%q", rr.Body.String())
	}

	var ownerScope, endpoint string
	if err := db.QueryRow(`SELECT owner_scope, controller_endpoint FROM public.devices WHERE serial=$1`, testSerial).Scan(&ownerScope, &endpoint); err != nil {
		t.Fatalf("query device row: %v", err)
	}
	if ownerScope != adminA {
		t.Fatalf("owner_scope changed: got=%q want=%q", ownerScope, adminA)
	}
	if endpoint != "openwifi-a2.routerarchitects.com" {
		t.Fatalf("controller_endpoint changed by admin B: got=%q", endpoint)
	}
}
