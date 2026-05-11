/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package config

import (
	"fmt"
	"net"
	"net/url"
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
	KeycloakAccessTokenAlg string
	DPoPAllowedAlgs        []string
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
	if err := validateJWKSURL(cfg.KeycloakJWKSURL); err != nil {
		return nil, err
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
	var err error
	if cfg.KeycloakAccessTokenAlg, err = parseJWTAlgEnv("KEYCLOAK_ACCESS_TOKEN_ALG", "RS256"); err != nil {
		return nil, err
	}
	if cfg.DPoPAllowedAlgs, err = parseJWTAlgListEnv("DPOP_ALLOWED_ALGS", []string{"ES256"}); err != nil {
		return nil, err
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
	for _, cidr := range cfg.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXY_CIDRS contains invalid CIDR %q", cidr)
		}
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

func parseJWTAlgEnv(key, fallback string) (string, error) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		v = fallback
	}
	switch v {
	case "RS256", "ES256":
		return v, nil
	default:
		return "", fmt.Errorf("%s must be one of RS256, ES256", key)
	}
}

func parseJWTAlgListEnv(key string, fallback []string) ([]string, error) {
	raw, set := os.LookupEnv(key)
	if !set {
		return fallback, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		alg := strings.TrimSpace(p)
		if alg == "" {
			continue
		}
		switch alg {
		case "RS256", "ES256":
			out = append(out, alg)
		default:
			return nil, fmt.Errorf("%s contains invalid value %q (allowed: RS256, ES256)", key, alg)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s must not be empty", key)
	}
	return out, nil
}

func validateJWKSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("KEYCLOAK_JWKS_URL is invalid: %w", err)
	}
	if strings.TrimSpace(u.Scheme) == "" {
		return fmt.Errorf("KEYCLOAK_JWKS_URL must include scheme")
	}
	if strings.TrimSpace(u.Host) == "" {
		return fmt.Errorf("KEYCLOAK_JWKS_URL must include host")
	}

	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := strings.TrimSpace(strings.ToLower(u.Hostname()))
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("KEYCLOAK_JWKS_URL must use https unless host is localhost/loopback")
	default:
		return fmt.Errorf("KEYCLOAK_JWKS_URL must use http or https")
	}
}
