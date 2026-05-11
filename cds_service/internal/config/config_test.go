/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package config

import (
	"strings"
	"testing"
)

func setRequiredAuthEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AUTH_MODE", "keycloak-dpop")
	t.Setenv("KEYCLOAK_ISSUER_URL", "http://127.0.0.1/test-realm")
	t.Setenv("KEYCLOAK_JWKS_URL", "http://127.0.0.1/jwks")
	t.Setenv("KEYCLOAK_AUDIENCE", "cds-service")
	t.Setenv("KEYCLOAK_REQUIRED_ROLE", "cds-admin")
	t.Setenv("KEYCLOAK_ADMIN_UI_CLIENT_ID", "cds-admin-ui")
	t.Setenv("KEYCLOAK_ACCESS_TOKEN_ALG", "RS256")
	t.Setenv("DPOP_ALLOWED_ALGS", "ES256")
}

func TestTrustedProxyCIDRsValidation(t *testing.T) {
	t.Run("valid single CIDR accepted", func(t *testing.T) {
		setRequiredAuthEnv(t)
		t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
		if _, err := Load(); err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("valid comma separated CIDRs with spaces accepted", func(t *testing.T) {
		setRequiredAuthEnv(t)
		t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32, ::1/128")
		if _, err := Load(); err != nil {
			t.Fatalf("expected success, got error: %v", err)
		}
	})

	t.Run("empty value rejected", func(t *testing.T) {
		setRequiredAuthEnv(t)
		t.Setenv("TRUSTED_PROXY_CIDRS", "   ")
		_, err := Load()
		if err == nil {
			t.Fatalf("expected error for empty TRUSTED_PROXY_CIDRS")
		}
		if !strings.Contains(err.Error(), "TRUSTED_PROXY_CIDRS is required") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid CIDR rejected", func(t *testing.T) {
		setRequiredAuthEnv(t)
		t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32,not-a-cidr")
		_, err := Load()
		if err == nil {
			t.Fatalf("expected error for invalid TRUSTED_PROXY_CIDRS")
		}
		if !strings.Contains(err.Error(), "invalid CIDR") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestJWTAlgorithmConfigValidation(t *testing.T) {
	t.Run("defaults are applied when envs are absent", func(t *testing.T) {
		t.Setenv("AUTH_MODE", "keycloak-dpop")
		t.Setenv("KEYCLOAK_ISSUER_URL", "http://127.0.0.1/test-realm")
		t.Setenv("KEYCLOAK_JWKS_URL", "http://127.0.0.1/jwks")
		t.Setenv("KEYCLOAK_AUDIENCE", "cds-service")
		t.Setenv("KEYCLOAK_REQUIRED_ROLE", "cds-admin")
		t.Setenv("KEYCLOAK_ADMIN_UI_CLIENT_ID", "cds-admin-ui")
		t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		if cfg.KeycloakAccessTokenAlg != "RS256" {
			t.Fatalf("got alg=%q", cfg.KeycloakAccessTokenAlg)
		}
		if len(cfg.DPoPAllowedAlgs) != 1 || cfg.DPoPAllowedAlgs[0] != "ES256" {
			t.Fatalf("got DPoPAllowedAlgs=%v", cfg.DPoPAllowedAlgs)
		}
	})

	t.Run("invalid KEYCLOAK_ACCESS_TOKEN_ALG rejected", func(t *testing.T) {
		setRequiredAuthEnv(t)
		t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
		t.Setenv("KEYCLOAK_ACCESS_TOKEN_ALG", "HS256")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "KEYCLOAK_ACCESS_TOKEN_ALG") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("empty DPOP_ALLOWED_ALGS rejected", func(t *testing.T) {
		setRequiredAuthEnv(t)
		t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
		t.Setenv("DPOP_ALLOWED_ALGS", "   ")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "DPOP_ALLOWED_ALGS must not be empty") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid DPOP_ALLOWED_ALGS entry rejected", func(t *testing.T) {
		setRequiredAuthEnv(t)
		t.Setenv("TRUSTED_PROXY_CIDRS", "127.0.0.1/32")
		t.Setenv("DPOP_ALLOWED_ALGS", "ES256,HS256")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "DPOP_ALLOWED_ALGS contains invalid value") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestJWKSURLValidation(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{
			name:    "https URL allowed",
			raw:     "https://keycloak.example.com/realms/cds/protocol/openid-connect/certs",
			wantErr: false,
		},
		{
			name:    "http localhost allowed",
			raw:     "http://localhost:8080/jwks",
			wantErr: false,
		},
		{
			name:    "http 127.0.0.1 allowed",
			raw:     "http://127.0.0.1:8080/jwks",
			wantErr: false,
		},
		{
			name:    "http ipv6 loopback allowed",
			raw:     "http://[::1]:8080/jwks",
			wantErr: false,
		},
		{
			name:    "http non loopback rejected",
			raw:     "http://keycloak.example.com/jwks",
			wantErr: true,
		},
		{
			name:    "unsupported scheme rejected",
			raw:     "ftp://keycloak.example.com/jwks",
			wantErr: true,
		},
		{
			name:    "missing scheme rejected",
			raw:     "keycloak.example.com/jwks",
			wantErr: true,
		},
		{
			name:    "missing host rejected",
			raw:     "https:///jwks",
			wantErr: true,
		},
		{
			name:    "malformed URL rejected",
			raw:     "://bad",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateJWKSURL(tc.raw)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected success, got err=%v", err)
			}
		})
	}
}
