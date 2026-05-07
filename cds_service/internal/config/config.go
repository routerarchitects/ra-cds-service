/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	PostgresDSN string
	HTTPAddr    string

	AuthMode               string
	KeycloakIssuerURL      string
	KeycloakJWKSURL        string
	KeycloakAudience       string
	KeycloakRequiredRole   string
	KeycloakAdminUIClient  string
	DPoPRequired           bool
	DPoPJtiCacheTTLSeconds int
	DPoPProofMaxAgeSeconds int
	DPoPClockSkewSeconds   int
	JWKSCacheTTLSeconds    int
	TrustedProxyCIDRs      []string
}

func Load() (*Config, error) {
	cfg := &Config{
		PostgresDSN:           os.Getenv("POSTGRES_DSN"),
		HTTPAddr:              os.Getenv("HTTP_ADDR"),
		AuthMode:              os.Getenv("AUTH_MODE"),
		KeycloakIssuerURL:     os.Getenv("KEYCLOAK_ISSUER_URL"),
		KeycloakJWKSURL:       os.Getenv("KEYCLOAK_JWKS_URL"),
		KeycloakAudience:      os.Getenv("KEYCLOAK_AUDIENCE"),
		KeycloakRequiredRole:  os.Getenv("KEYCLOAK_REQUIRED_ROLE"),
		KeycloakAdminUIClient: os.Getenv("KEYCLOAK_ADMIN_UI_CLIENT_ID"),
	}

	if cfg.PostgresDSN == "" {
		cfg.PostgresDSN = "postgres://postgres:password@postgres:5432/cds?sslmode=disable"
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":8080"
	}
	if cfg.AuthMode == "" {
		return nil, fmt.Errorf("AUTH_MODE is required")
	}
	if cfg.AuthMode != "keycloak-dpop" {
		return nil, fmt.Errorf("AUTH_MODE must be keycloak-dpop")
	}
	if cfg.KeycloakIssuerURL == "" {
		return nil, fmt.Errorf("KEYCLOAK_ISSUER_URL is required")
	}
	if cfg.KeycloakJWKSURL == "" {
		return nil, fmt.Errorf("KEYCLOAK_JWKS_URL is required")
	}
	if cfg.KeycloakAudience == "" {
		return nil, fmt.Errorf("KEYCLOAK_AUDIENCE is required")
	}
	if cfg.KeycloakRequiredRole == "" {
		return nil, fmt.Errorf("KEYCLOAK_REQUIRED_ROLE is required")
	}
	if cfg.KeycloakAdminUIClient == "" {
		return nil, fmt.Errorf("KEYCLOAK_ADMIN_UI_CLIENT_ID is required")
	}

	dpopRequired, err := parseBoolEnv("DPOP_REQUIRED", true)
	if err != nil {
		return nil, err
	}
	cfg.DPoPRequired = dpopRequired

	if cfg.DPoPJtiCacheTTLSeconds, err = parseIntEnv("DPOP_JTI_CACHE_TTL_SECONDS", 300); err != nil {
		return nil, err
	}
	if cfg.DPoPProofMaxAgeSeconds, err = parseIntEnv("DPOP_PROOF_MAX_AGE_SECONDS", 300); err != nil {
		return nil, err
	}
	if cfg.DPoPClockSkewSeconds, err = parseIntEnv("DPOP_CLOCK_SKEW_SECONDS", 30); err != nil {
		return nil, err
	}
	if cfg.JWKSCacheTTLSeconds, err = parseIntEnv("JWKS_CACHE_TTL_SECONDS", 300); err != nil {
		return nil, err
	}

	cfg.TrustedProxyCIDRs = parseListEnv("TRUSTED_PROXY_CIDRS")
	if len(cfg.TrustedProxyCIDRs) == 0 {
		return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS is required")
	}
	return cfg, nil
}

func parseIntEnv(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if strings.TrimSpace(v) == "" {
		return fallback, nil
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	if i <= 0 {
		return 0, fmt.Errorf("%s must be > 0", key)
	}
	return i, nil
}

func parseBoolEnv(key string, fallback bool) (bool, error) {
	v := os.Getenv(key)
	if strings.TrimSpace(v) == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return b, nil
}

func parseListEnv(key string) []string {
	raw := os.Getenv(key)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
