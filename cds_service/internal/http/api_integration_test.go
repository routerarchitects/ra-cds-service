/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"cds/internal/adapters/postgres"
	"cds/internal/config"
	"cds/internal/services"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	_ "github.com/lib/pq"
)

const (
	testOwnerToken = "root-token"
	testSerial     = "b4:6a:d4:45:f0:19"
	testEndpoint   = "openwifi3.routerarchitects.com"
)

func mustOpenTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set; skipping integration tests")
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

func resetDevicesTable(t *testing.T, db *sql.DB) {
	t.Helper()

	const schema = `
CREATE TABLE IF NOT EXISTS public.devices (
  serial TEXT PRIMARY KEY,
  controller_endpoint TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  owner_token TEXT
);
TRUNCATE TABLE public.devices;
`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("prepare devices table: %v", err)
	}
}

func newRootValidator(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" || r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "invalid token header", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tokenInfo": map[string]string{"access_token": token},
			"userInfo":  map[string]string{"userRole": "root"},
		})
	}))
}

func newIntegrationRouter(t *testing.T) (*http.ServeMux, *sql.DB) {
	t.Helper()

	db := mustOpenTestDB(t)
	resetDevicesTable(t, db)

	repo := postgres.NewRepo(db)
	svc := services.New(repo)
	validator := newRootValidator(t)
	t.Cleanup(validator.Close)
	t.Cleanup(func() { _ = db.Close() })

	cfg := &config.Config{
		ValidateTokenURL: validator.URL,
	}
	return NewRouterWithConfig(cfg, svc), db
}

func performJSONRequest(router http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func adminHeaders() map[string]string {
	return map[string]string{
		"X-Auth-Token": testOwnerToken,
		"Content-Type": "application/json",
		"Accept":       "application/json",
	}
}

func TestCRUDAndDeviceFacingAPIIntegration(t *testing.T) {
	router, _ := newIntegrationRouter(t)

	postBody := `{"serial":"B4:6A:D4:45:F0:19","controller_endpoint":"` + testEndpoint + `"}`
	rr := performJSONRequest(router, http.MethodPost, "/v1/device", postBody, adminHeaders())
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /v1/device got %d, want %d (body=%s)", rr.Code, http.StatusCreated, rr.Body.String())
	}

	rr = performJSONRequest(router, http.MethodGet, "/v1/device", "", adminHeaders())
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

	rr = performJSONRequest(router, http.MethodGet, "/v1/devices/B4:6A:D4:45:F0:19", "", map[string]string{
		"X-SSL-Client-Verify": "SUCCESS",
		"Accept":              "application/json",
	})
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
	rr = performJSONRequest(router, http.MethodPut, "/v1/device", putBody, adminHeaders())
	if rr.Code != http.StatusNoContent {
		t.Fatalf("PUT /v1/device got %d, want %d (body=%s)", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	rr = performJSONRequest(router, http.MethodGet, "/v1/devices/B4:6A:D4:45:F0:19", "", map[string]string{
		"X-SSL-Client-Verify": "SUCCESS",
		"Accept":              "application/json",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /v1/devices/{serial} after update got %d, want %d (body=%s)", rr.Code, http.StatusOK, rr.Body.String())
	}
	device = nil
	if err := json.NewDecoder(rr.Body).Decode(&device); err != nil {
		t.Fatalf("decode device response after update: %v", err)
	}
	if device["serial"] != testSerial || device["controller_endpoint"] != "openwifi9.routerarchitects.com" {
		t.Fatalf("unexpected device response after update: %#v", device)
	}

	rr = performJSONRequest(router, http.MethodDelete, "/v1/device", `{"serial":"B4:6A:D4:45:F0:19"}`, adminHeaders())
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE /v1/device got %d, want %d (body=%s)", rr.Code, http.StatusNoContent, rr.Body.String())
	}

	rr = performJSONRequest(router, http.MethodGet, "/v1/device", "", adminHeaders())
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
