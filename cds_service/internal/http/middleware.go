/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"cds/internal/config"
)

type ctxKey string

const ctxKeyOwnerToken ctxKey = "ownerToken"

type tokenValidationResponse struct {
	TokenInfo struct {
		AccessToken string `json:"access_token"`
	} `json:"tokenInfo"`
	UserInfo struct {
		UserRole string `json:"userRole"`
	} `json:"userInfo"`
}

// Device mTLS guard (existing behavior)
func RequireClientCert(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-SSL-Client-Verify") != "SUCCESS" {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// New admin validator middleware:
// - reads X-Auth-Token
// - calls VALIDATE_TOKEN_URL with ?token=... and Authorization: Bearer ...
// - requires userRole == "root"
// - injects token into ctx
func RequireValidatedAdmin(cfg *config.Config, next http.Handler) http.Handler {
	client := &http.Client{Timeout: 10 * time.Second}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Auth-Token")
		if token == "" {
			http.Error(w, "missing X-Auth-Token", http.StatusForbidden)
			return
		}

		u, err := url.Parse(cfg.ValidateTokenURL)
		if err != nil {
			http.Error(w, "server validator URL invalid", http.StatusInternalServerError)
			return
		}
		q := u.Query()
		q.Set("token", token)
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, u.String(), nil)
		if err != nil {
			http.Error(w, "failed to build validation request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "security token validation failed", http.StatusForbidden)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			http.Error(w, "security token validation failed", http.StatusForbidden)
			return
		}

		var tv tokenValidationResponse
		if err := json.NewDecoder(resp.Body).Decode(&tv); err != nil {
			http.Error(w, "invalid validation response", http.StatusForbidden)
			return
		}
		if tv.UserInfo.UserRole != "root" {
			http.Error(w, "error:Only root user is allowed.", http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), ctxKeyOwnerToken, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Extract validated owner token from ctx
func GetOwnerTokenFromCtx(r *http.Request) (string, error) {
	v := r.Context().Value(ctxKeyOwnerToken)
	if v == nil {
		return "", fmt.Errorf("owner token missing from context")
	}
	if s, ok := v.(string); ok && s != "" {
		return s, nil
	}
	return "", fmt.Errorf("owner token missing from context")
}

