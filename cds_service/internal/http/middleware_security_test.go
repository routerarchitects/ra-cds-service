/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cds/internal/config"
)

type testKeyMaterial struct {
	key *rsa.PrivateKey
	kid string
}

type jwksState struct {
	mu   sync.Mutex
	keys []map[string]any
	hits int
}

func (s *jwksState) setKeys(keys []map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = keys
}

func (s *jwksState) hitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func (s *jwksState) handler(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.hits++
	keys := s.keys
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func newRSAKey(t *testing.T, kid string) *testKeyMaterial {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return &testKeyMaterial{key: k, kid: kid}
}

func jwkFromRSA(km *testKeyMaterial) map[string]any {
	pub := km.key.Public().(*rsa.PublicKey)
	return map[string]any{
		"kty": "RSA",
		"kid": km.kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func signJWTForTest(t *testing.T, privateKey *rsa.PrivateKey, header map[string]any, payload map[string]any) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	h := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func thumbprintRSA(pub *rsa.PublicKey) string {
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	canonical := `{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type tokenOpts struct {
	issuer       string
	audience     []string
	clientID     string
	roleAudience string
	roles        []string
	includeCNF   bool
	kid          string
	expiryOffset time.Duration
}

func buildAccessToken(t *testing.T, signer *testKeyMaterial, dpopPub *rsa.PublicKey, opts tokenOpts) string {
	t.Helper()
	now := time.Now()
	issuer := opts.issuer
	if issuer == "" {
		issuer = "https://keycloak.example.com/realms/cds"
	}
	aud := opts.audience
	if len(aud) == 0 {
		aud = []string{"cds-service"}
	}
	clientID := opts.clientID
	if clientID == "" {
		clientID = "cds-admin-ui"
	}
	roleAud := opts.roleAudience
	if roleAud == "" {
		roleAud = "cds-service"
	}
	roles := opts.roles
	if roles == nil {
		roles = []string{"cds-admin"}
	}
	exp := now.Add(1 * time.Hour)
	if opts.expiryOffset != 0 {
		exp = now.Add(opts.expiryOffset)
	}
	payload := map[string]any{
		"iss": issuer,
		"sub": "admin-subject",
		"aud": aud,
		"exp": exp.Unix(),
		"iat": now.Unix(),
		"azp": clientID,
		"resource_access": map[string]any{
			roleAud: map[string]any{
				"roles": roles,
			},
		},
	}
	if opts.includeCNF || opts.includeCNF == false {
		// default include unless explicitly false via pointerless toggle check below
	}
	if opts.includeCNF || !opts.includeCNF && dpopPub != nil {
		if opts.includeCNF {
			payload["cnf"] = map[string]any{"jkt": thumbprintRSA(dpopPub)}
		}
	}
	if !opts.includeCNF {
		delete(payload, "cnf")
	}
	kid := signer.kid
	if opts.kid != "" {
		kid = opts.kid
	}
	return signJWTForTest(t, signer.key, map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": kid,
	}, payload)
}

type dpopOpts struct {
	method    string
	htu       string
	iat       int64
	jti       string
	ath       string
	tamperSig bool
}

func buildDPoPProof(t *testing.T, key *rsa.PrivateKey, opts dpopOpts) string {
	t.Helper()
	pub := key.Public().(*rsa.PublicKey)
	method := opts.method
	if method == "" {
		method = http.MethodGet
	}
	iat := opts.iat
	if iat == 0 {
		iat = time.Now().Unix()
	}
	jti := opts.jti
	if jti == "" {
		jti = "jti-" + base64.RawURLEncoding.EncodeToString([]byte(time.Now().String()))
	}
	proof := signJWTForTest(t, key, map[string]any{
		"alg": "RS256",
		"typ": "dpop+jwt",
		"jwk": map[string]any{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		},
	}, map[string]any{
		"htu": opts.htu,
		"htm": method,
		"iat": iat,
		"jti": jti,
		"ath": opts.ath,
	})
	if opts.tamperSig {
		parts := strings.Split(proof, ".")
		if len(parts) != 3 {
			return proof
		}
		payload := parts[1]
		if len(payload) > 0 {
			if strings.HasSuffix(payload, "A") {
				payload = payload[:len(payload)-1] + "B"
			} else {
				payload = payload[:len(payload)-1] + "A"
			}
			parts[1] = payload
		}
		return strings.Join(parts, ".")
	}
	return proof
}

func newMiddlewareTestConfig(jwksURL string, dpopRequired bool) *config.Config {
	return &config.Config{
		AuthMode:               "keycloak-dpop",
		KeycloakIssuerURL:      "https://keycloak.example.com/realms/cds",
		KeycloakJWKSURL:        jwksURL,
		KeycloakAudience:       "cds-service",
		KeycloakRequiredRole:   "cds-admin",
		KeycloakAdminUIClient:  "cds-admin-ui",
		DPoPRequired:           dpopRequired,
		DPoPJtiCacheTTLSeconds: 300,
		DPoPProofMaxAgeSeconds: 300,
		DPoPClockSkewSeconds:   30,
		JWKSCacheTTLSeconds:    300,
		TrustedProxyCIDRs:      []string{"127.0.0.1/32"},
	}
}

func executeAdminRequest(t *testing.T, cfg *config.Config, method, target, authorization, dpop, remoteAddr string, extraHeaders map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	h := RequireKeycloakDPoPAdmin(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(method, target, nil)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if dpop != "" {
		req.Header.Set("DPoP", dpop)
	}
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestAdminJWTValidationFailures(t *testing.T) {
	tokenKey := newRSAKey(t, "kid-1")
	dpopKey := newRSAKey(t, "dpop-1")
	jwks := &jwksState{}
	jwks.setKeys([]map[string]any{jwkFromRSA(tokenKey)})
	srv := httptest.NewServer(http.HandlerFunc(jwks.handler))
	defer srv.Close()

	t.Run("missing Authorization rejected", func(t *testing.T) {
		cfg := newMiddlewareTestConfig(srv.URL, false)
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "", "", "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "missing Authorization header") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("Bearer rejected", func(t *testing.T) {
		cfg := newMiddlewareTestConfig(srv.URL, false)
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "Bearer token", "", "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "Authorization scheme must be DPoP") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("malformed token rejected", func(t *testing.T) {
		cfg := newMiddlewareTestConfig(srv.URL, false)
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP not.a.jwt", "", "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid access token") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("wrong issuer rejected", func(t *testing.T) {
		cfg := newMiddlewareTestConfig(srv.URL, false)
		token := buildAccessToken(t, tokenKey, dpopKey.key.Public().(*rsa.PublicKey), tokenOpts{issuer: "https://wrong-issuer", includeCNF: true})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+token, "", "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid access token") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		cfg := newMiddlewareTestConfig(srv.URL, false)
		token := buildAccessToken(t, tokenKey, dpopKey.key.Public().(*rsa.PublicKey), tokenOpts{audience: []string{"other-service"}, includeCNF: true})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+token, "", "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid access token") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing required role rejected", func(t *testing.T) {
		cfg := newMiddlewareTestConfig(srv.URL, false)
		token := buildAccessToken(t, tokenKey, dpopKey.key.Public().(*rsa.PublicKey), tokenOpts{roles: []string{}, includeCNF: true})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+token, "", "", nil)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "missing required role") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("wrong role rejected", func(t *testing.T) {
		cfg := newMiddlewareTestConfig(srv.URL, false)
		token := buildAccessToken(t, tokenKey, dpopKey.key.Public().(*rsa.PublicKey), tokenOpts{roles: []string{"not-admin"}, includeCNF: true})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+token, "", "", nil)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "missing required role") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing cnf.jkt rejected", func(t *testing.T) {
		cfg := newMiddlewareTestConfig(srv.URL, false)
		token := buildAccessToken(t, tokenKey, dpopKey.key.Public().(*rsa.PublicKey), tokenOpts{includeCNF: false})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+token, "", "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid access token") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})
}

func TestUnknownKIDRefreshBehavior(t *testing.T) {
	tokenKey := newRSAKey(t, "kid-token")
	dpopKey := newRSAKey(t, "kid-dpop")
	jwks := &jwksState{}
	jwks.setKeys([]map[string]any{})
	srv := httptest.NewServer(http.HandlerFunc(jwks.handler))
	defer srv.Close()

	t.Run("unknown kid refresh succeeds when key appears", func(t *testing.T) {
		jwks.setKeys([]map[string]any{jwkFromRSA(tokenKey)})
		cfg := newMiddlewareTestConfig(srv.URL, false)
		token := buildAccessToken(t, tokenKey, dpopKey.key.Public().(*rsa.PublicKey), tokenOpts{includeCNF: true})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+token, "", "", nil)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
		if jwks.hitCount() != 1 {
			t.Fatalf("expected one refresh hit, got %d", jwks.hitCount())
		}
	})

	t.Run("unknown kid refresh fails when key still missing", func(t *testing.T) {
		jwks2 := &jwksState{}
		otherKey := newRSAKey(t, "other-kid")
		jwks2.setKeys([]map[string]any{jwkFromRSA(otherKey)})
		srv2 := httptest.NewServer(http.HandlerFunc(jwks2.handler))
		defer srv2.Close()
		cfg := newMiddlewareTestConfig(srv2.URL, false)
		token := buildAccessToken(t, tokenKey, dpopKey.key.Public().(*rsa.PublicKey), tokenOpts{includeCNF: true})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+token, "", "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "unknown access token kid after JWKS refresh") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
		if jwks2.hitCount() != 1 {
			t.Fatalf("expected one refresh hit, got %d", jwks2.hitCount())
		}
	})
}

func TestDPoPValidationScenarios(t *testing.T) {
	tokenKey := newRSAKey(t, "token-kid")
	dpopKey := newRSAKey(t, "dpop-kid")
	jwks := &jwksState{}
	jwks.setKeys([]map[string]any{jwkFromRSA(tokenKey)})
	srv := httptest.NewServer(http.HandlerFunc(jwks.handler))
	defer srv.Close()

	cfg := newMiddlewareTestConfig(srv.URL, true)
	accessToken := buildAccessToken(t, tokenKey, dpopKey.key.Public().(*rsa.PublicKey), tokenOpts{includeCNF: true})
	ath := hashAccessToken(accessToken)

	t.Run("missing DPoP header rejected", func(t *testing.T) {
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, "", "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "missing DPoP proof") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid DPoP signature rejected", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method:    http.MethodGet,
			htu:       "http://example.com/v1/device",
			ath:       ath,
			jti:       "sig-invalid",
			tamperSig: true,
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid DPoP proof") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("htm mismatch rejected", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodPost,
			htu:    "http://example.com/v1/device",
			ath:    ath,
			jti:    "wrong-htm",
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid DPoP proof") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("htu mismatch rejected", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://example.com/v1/other",
			ath:    ath,
			jti:    "wrong-htu",
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid DPoP proof htu") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("htu ignores query string", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://example.com/v1/device",
			ath:    ath,
			jti:    "htu-query",
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device?serial=abc", "DPoP "+accessToken, proof, "", nil)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("htu ignores fragment", func(t *testing.T) {
		actx := getAuthContext(cfg)
		req := httptest.NewRequest(http.MethodGet, "http://example.com/v1/device", nil)
		req.URL.Fragment = "frag"
		got, err := actx.expectedHTU(req)
		if err != nil {
			t.Fatalf("expectedHTU err: %v", err)
		}
		if got != "http://example.com/v1/device" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("stale iat rejected", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://example.com/v1/device",
			ath:    ath,
			jti:    "iat-stale",
			iat:    time.Now().Add(-10 * time.Minute).Unix(),
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid DPoP proof iat") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("future iat beyond skew rejected", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://example.com/v1/device",
			ath:    ath,
			jti:    "iat-future",
			iat:    time.Now().Add(2 * time.Minute).Unix(),
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid DPoP proof iat") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("ath mismatch rejected", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://example.com/v1/device",
			ath:    "bad-ath",
			jti:    "bad-ath",
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid DPoP proof") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("cnf.jkt mismatch rejected", func(t *testing.T) {
		otherKey := newRSAKey(t, "other-dpop")
		proof := buildDPoPProof(t, otherKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://example.com/v1/device",
			ath:    ath,
			jti:    "mismatch-jkt",
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "", nil)
		if rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "invalid DPoP proof") {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("replayed jti rejected and new jti accepted", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://example.com/v1/device",
			ath:    ath,
			jti:    "same-jti",
		})
		rr1 := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "", nil)
		if rr1.Code != http.StatusNoContent {
			t.Fatalf("first got %d body=%q", rr1.Code, rr1.Body.String())
		}
		rr2 := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "", nil)
		if rr2.Code != http.StatusUnauthorized || !strings.Contains(rr2.Body.String(), "replayed DPoP proof") {
			t.Fatalf("second got %d body=%q", rr2.Code, rr2.Body.String())
		}
		proof2 := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://example.com/v1/device",
			ath:    ath,
			jti:    "new-jti",
		})
		rr3 := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof2, "", nil)
		if rr3.Code != http.StatusNoContent {
			t.Fatalf("third got %d body=%q", rr3.Code, rr3.Body.String())
		}
	})
}

func TestTrustedProxyHTUReconstruction(t *testing.T) {
	tokenKey := newRSAKey(t, "token-kid")
	dpopKey := newRSAKey(t, "dpop-kid")
	jwks := &jwksState{}
	jwks.setKeys([]map[string]any{jwkFromRSA(tokenKey)})
	srv := httptest.NewServer(http.HandlerFunc(jwks.handler))
	defer srv.Close()

	cfg := newMiddlewareTestConfig(srv.URL, true)
	accessToken := buildAccessToken(t, tokenKey, dpopKey.key.Public().(*rsa.PublicKey), tokenOpts{includeCNF: true})
	ath := hashAccessToken(accessToken)

	t.Run("trusted proxy uses X-Forwarded headers", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "https://proxy.example.com:8443/v1/device",
			ath:    ath,
			jti:    "trusted-forwarded",
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://internal/v1/device", "DPoP "+accessToken, proof, "127.0.0.1:60000", map[string]string{
			"X-Forwarded-Proto": "https",
			"X-Forwarded-Host":  "proxy.example.com",
			"X-Forwarded-Port":  "8443",
		})
		if rr.Code != http.StatusNoContent {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("untrusted remote ignores X-Forwarded headers", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://example.com/v1/device",
			ath:    ath,
			jti:    "untrusted-ignore",
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "198.51.100.10:34567", map[string]string{
			"X-Forwarded-Proto": "https",
			"X-Forwarded-Host":  "evil.example.com",
			"X-Forwarded-Port":  "9443",
		})
		if rr.Code != http.StatusNoContent {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("Forwarded header explicitly ignored", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://example.com/v1/device",
			ath:    ath,
			jti:    "forwarded-ignored",
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://example.com/v1/device", "DPoP "+accessToken, proof, "198.51.100.10:34567", map[string]string{
			"Forwarded": "proto=https;host=forwarded.example.com:443",
		})
		if rr.Code != http.StatusNoContent {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("default ports normalized for http and https", func(t *testing.T) {
		proofHTTP := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "http://proxy.example.com/v1/device",
			ath:    ath,
			jti:    "default-80",
		})
		rrHTTP := executeAdminRequest(t, cfg, http.MethodGet, "http://internal/v1/device", "DPoP "+accessToken, proofHTTP, "127.0.0.1:60000", map[string]string{
			"X-Forwarded-Proto": "http",
			"X-Forwarded-Host":  "proxy.example.com",
			"X-Forwarded-Port":  "80",
		})
		if rrHTTP.Code != http.StatusNoContent {
			t.Fatalf("http got %d body=%q", rrHTTP.Code, rrHTTP.Body.String())
		}
		proofHTTPS := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "https://proxy.example.com/v1/device",
			ath:    ath,
			jti:    "default-443",
		})
		rrHTTPS := executeAdminRequest(t, cfg, http.MethodGet, "http://internal/v1/device", "DPoP "+accessToken, proofHTTPS, "127.0.0.1:60000", map[string]string{
			"X-Forwarded-Proto": "https",
			"X-Forwarded-Host":  "proxy.example.com",
			"X-Forwarded-Port":  "443",
		})
		if rrHTTPS.Code != http.StatusNoContent {
			t.Fatalf("https got %d body=%q", rrHTTPS.Code, rrHTTPS.Body.String())
		}
	})

	t.Run("non-default forwarded port included in htu", func(t *testing.T) {
		proof := buildDPoPProof(t, dpopKey.key, dpopOpts{
			method: http.MethodGet,
			htu:    "https://proxy.example.com:8443/v1/device",
			ath:    ath,
			jti:    "nondefault-port",
		})
		rr := executeAdminRequest(t, cfg, http.MethodGet, "http://internal/v1/device", "DPoP "+accessToken, proof, "127.0.0.1:60000", map[string]string{
			"X-Forwarded-Proto": "https",
			"X-Forwarded-Host":  "proxy.example.com",
			"X-Forwarded-Port":  "8443",
		})
		if rr.Code != http.StatusNoContent {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})
}

func TestRouteBehaviorWithNewAuthContract(t *testing.T) {
	tokenKey := newRSAKey(t, "token-kid")
	jwks := &jwksState{}
	jwks.setKeys([]map[string]any{jwkFromRSA(tokenKey)})
	srv := httptest.NewServer(http.HandlerFunc(jwks.handler))
	defer srv.Close()

	cfg := newMiddlewareTestConfig(srv.URL, true)
	router := NewRouterWithConfig(cfg, nil)

	t.Run("X-Auth-Token alone rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/device", nil)
		req.Header.Set("X-Auth-Token", "legacy-token")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("DELETE /v1/device without serial is not delete success path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/v1/device", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code == http.StatusNoContent {
			t.Fatalf("unexpected success for DELETE /v1/device")
		}
	})

	t.Run("health endpoint does not require auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d body=%q", rr.Code, rr.Body.String())
		}
	})

	t.Run("device-facing endpoint uses mTLS header simulation and no DPoP", func(t *testing.T) {
		mtlsOnly := RequireClientCert(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		reqNoCert := httptest.NewRequest(http.MethodGet, "/v1/devices/abc", nil)
		rrNoCert := httptest.NewRecorder()
		mtlsOnly.ServeHTTP(rrNoCert, reqNoCert)
		if rrNoCert.Code != http.StatusUnauthorized {
			t.Fatalf("without cert got %d body=%q", rrNoCert.Code, rrNoCert.Body.String())
		}
		reqWithCert := httptest.NewRequest(http.MethodGet, "/v1/devices/abc", nil)
		reqWithCert.Header.Set("X-SSL-Client-Verify", "SUCCESS")
		rrWithCert := httptest.NewRecorder()
		mtlsOnly.ServeHTTP(rrWithCert, reqWithCert)
		if rrWithCert.Code != http.StatusNoContent {
			t.Fatalf("with cert got %d body=%q", rrWithCert.Code, rrWithCert.Body.String())
		}
	})
}
