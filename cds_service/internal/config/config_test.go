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
