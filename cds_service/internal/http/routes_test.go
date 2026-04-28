package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cds/internal/config"
)

// Create router for testing
func newTestRouter() *http.ServeMux {
	cfg := &config.Config{
		ValidateTokenURL: "http://127.0.0.1/validate",
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

	// Allowed methods reach middleware but fail auth (no token)
	assertStatus(t, r, "GET", "/v1/device", http.StatusForbidden)
	assertStatus(t, r, "POST", "/v1/device", http.StatusForbidden)
	assertStatus(t, r, "PUT", "/v1/device", http.StatusForbidden)
	assertStatus(t, r, "DELETE", "/v1/device", http.StatusForbidden)

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
