/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cds/internal/config"
)

// Create router for testing
func newTestRouter() http.Handler {
	cfg := &config.Config{
		AuthMode:               "keycloak-dpop",
		KeycloakIssuerURL:      "https://issuer.example/realms/cds",
		KeycloakJWKSURL:        "http://127.0.0.1/keys",
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
	return NewRouterWithConfig(cfg, nil)
}

// Helper to check status code
func assertStatus(t *testing.T, router http.Handler, method, path string, want int) {
	req := httptest.NewRequest(method, path, nil)
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	if rr.Code != want {
		t.Fatalf("%s %s → got %d, want %d (body=%s)",
			method, path, rr.Code, want, rr.Body.String())
	}
}

// Test health endpoint
func TestHealth(t *testing.T) {
	r := newTestRouter()
	assertStatus(t, r, "GET", "/health", http.StatusOK)
}

// Test admin API method enforcement
func TestAdminMethodEnforcement(t *testing.T) {
	r := newTestRouter()

	// Allowed methods reach middleware but fail auth (no Authorization)
	assertStatus(t, r, "GET", "/v1/device", http.StatusUnauthorized)
	assertStatus(t, r, "POST", "/v1/device", http.StatusUnauthorized)
	assertStatus(t, r, "PUT", "/v1/device", http.StatusUnauthorized)
	assertStatus(t, r, "DELETE", "/v1/device/abc", http.StatusUnauthorized)

	// Unsupported method → 405
	assertStatus(t, r, "PATCH", "/v1/device", http.StatusMethodNotAllowed)
}

// Test device lookup (mTLS) method enforcement
func TestDeviceLookupMethodEnforcement(t *testing.T) {
	r := newTestRouter()

	// GET reaches mTLS middleware but fails without cert → 401
	assertStatus(t, r, "GET", "/v1/devices/abc", http.StatusUnauthorized)

	// Unsupported method → 405
	assertStatus(t, r, "POST", "/v1/devices/abc", http.StatusMethodNotAllowed)
}

// Optional: test unknown route
func TestUnknownRoute(t *testing.T) {
	r := newTestRouter()
	assertStatus(t, r, "GET", "/unknown", http.StatusNotFound)
}

func TestRequestIDGeneratedWhenAbsent(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /health got %d", rr.Code)
	}
	if rr.Header().Get("X-Request-Id") == "" {
		t.Fatalf("expected X-Request-Id to be set")
	}
}

func TestRequestIDPropagatedWhenProvided(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Request-Id", "req-123")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /health got %d", rr.Code)
	}
	if got := rr.Header().Get("X-Request-Id"); got != "req-123" {
		t.Fatalf("expected propagated request id, got %q", got)
	}
}
