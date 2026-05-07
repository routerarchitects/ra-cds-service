/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cds/internal/adapters/logger"
	"cds/internal/config"
)

type ctxKey string

const ctxKeyOwnerScope ctxKey = "ownerScope"

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

type authContext struct {
	cfg          *config.Config
	client       *http.Client
	jwks         *jwksCache
	replay       *jtiReplayCache
	trustedCIDRs []*net.IPNet
}

var (
	authCtxMu sync.Mutex
	authCtxBy = map[*config.Config]*authContext{}
)

func RequireKeycloakDPoPAdmin(cfg *config.Config, next http.Handler) http.Handler {
	actx := getAuthContext(cfg)
	log := logger.New()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := parseAuthorizationDPoP(r.Header.Get("Authorization"))
		if err != nil {
			reason := "jwt_invalid"
			if errors.Is(err, errJWTMissing) {
				reason = "jwt_missing"
			} else if errors.Is(err, errJWTSchemeInvalid) {
				reason = "jwt_scheme_invalid"
			}
			logAdminAuth(log, reason, r, "", nil)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		kid := extractJWTKid(accessToken)

		tokenClaims, kidKnown, err := actx.validateAccessToken(accessToken)
		if err != nil && errors.Is(err, errUnknownKID) && !kidKnown {
			logAdminAuth(log, "unknown_kid_detected", r, kid, nil)
			logAdminAuth(log, "jwks_refresh_started", r, kid, nil)
			if refreshErr := actx.jwks.refresh(r.Context(), actx.client, cfg.KeycloakJWKSURL); refreshErr != nil {
				logAdminAuth(log, "jwks_fetch_failed", r, kid, nil)
				http.Error(w, "failed to fetch Keycloak JWKS", http.StatusInternalServerError)
				return
			}
			logAdminAuth(log, "jwks_refresh_succeeded", r, kid, nil)
			tokenClaims, _, err = actx.validateAccessToken(accessToken)
			if err == nil {
				logAdminAuth(log, "retry_succeeded", r, kid, nil)
			}
		}
		if err != nil {
			if errors.Is(err, errUnknownKID) {
				logAdminAuth(log, "unknown_kid_refresh_failed", r, kid, nil)
				http.Error(w, "unknown access token kid after JWKS refresh", http.StatusUnauthorized)
				return
			}
			if errors.Is(err, errInvalidAdminClient) || errors.Is(err, errMissingRequiredRole) {
				logAdminAuth(log, "role_missing", r, kid, nil)
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			logAdminAuth(log, "jwt_invalid", r, kid, nil)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if cfg.DPoPRequired {
			dpopProof := r.Header.Get("DPoP")
			if strings.TrimSpace(dpopProof) == "" {
				logAdminAuth(log, "dpop_missing", r, kid, nil)
				http.Error(w, "missing DPoP proof", http.StatusUnauthorized)
				return
			}
			if err := actx.validateDPoPProof(r, dpopProof, accessToken, tokenClaims.CnfJKT); err != nil {
				status := http.StatusUnauthorized
				if errors.Is(err, errInvalidConfig) {
					status = http.StatusInternalServerError
				}
				reason := "dpop_invalid"
				var trusted *bool
				if errors.Is(err, errDPoPHTUMismatch) {
					reason = "dpop_htu_mismatch"
					v := actx.isTrustedRemote(r.RemoteAddr)
					trusted = &v
				} else if errors.Is(err, errDPoPReplay) {
					reason = "dpop_replay"
				} else if errors.Is(err, errDPoPJKTMismatch) {
					reason = "dpop_jkt_mismatch"
				}
				logAdminAuth(log, reason, r, kid, trusted)
				http.Error(w, err.Error(), status)
				return
			}
		}

		ctx := context.WithValue(r.Context(), ctxKeyOwnerScope, tokenClaims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetOwnerScopeFromCtx(r *http.Request) (string, error) {
	v := r.Context().Value(ctxKeyOwnerScope)
	if v == nil {
		return "", fmt.Errorf("owner scope missing from context")
	}
	if s, ok := v.(string); ok && s != "" {
		return s, nil
	}
	return "", fmt.Errorf("owner scope missing from context")
}

func getAuthContext(cfg *config.Config) *authContext {
	authCtxMu.Lock()
	defer authCtxMu.Unlock()
	if v, ok := authCtxBy[cfg]; ok {
		return v
	}
	cidrs := make([]*net.IPNet, 0, len(cfg.TrustedProxyCIDRs))
	for _, c := range cfg.TrustedProxyCIDRs {
		_, ipn, err := net.ParseCIDR(c)
		if err == nil {
			cidrs = append(cidrs, ipn)
		}
	}
	v := &authContext{
		cfg:          cfg,
		client:       &http.Client{Timeout: 10 * time.Second},
		jwks:         newJWKSCache(time.Duration(cfg.JWKSCacheTTLSeconds) * time.Second),
		replay:       newJTIReplayCache(time.Duration(cfg.DPoPJtiCacheTTLSeconds) * time.Second),
		trustedCIDRs: cidrs,
	}
	authCtxBy[cfg] = v
	return v
}

var (
	errUnknownKID          = errors.New("unknown access token kid after JWKS refresh")
	errInvalidConfig       = errors.New("server Keycloak configuration invalid")
	errInvalidAdminClient  = errors.New("invalid admin client")
	errMissingRequiredRole = errors.New("missing required role")
	errJWTMissing          = errors.New("missing Authorization header")
	errJWTSchemeInvalid    = errors.New("Authorization scheme must be DPoP")
	errJWTInvalid          = errors.New("invalid access token")
	errDPoPInvalid         = errors.New("invalid DPoP proof")
	errDPoPHTUMismatch     = errors.New("invalid DPoP proof htu")
	errDPoPIatInvalid      = errors.New("invalid DPoP proof iat")
	errDPoPReplay          = errors.New("replayed DPoP proof")
	errDPoPJKTMismatch     = errors.New("invalid DPoP proof")
)

func parseAuthorizationDPoP(header string) (string, error) {
	if strings.TrimSpace(header) == "" {
		return "", errJWTMissing
	}
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "DPoP") {
		return "", errJWTSchemeInvalid
	}
	if strings.TrimSpace(parts[1]) == "" {
		return "", errJWTInvalid
	}
	return strings.TrimSpace(parts[1]), nil
}

type tokenClaims struct {
	Subject     string
	Issuer      string
	Audience    []string
	ExpiresAt   int64
	NotBefore   int64
	AZP         string
	ClientID    string
	CnfJKT      string
	RawRolesMap map[string]any
}

func (a *authContext) validateAccessToken(token string) (*tokenClaims, bool, error) {
	header, payload, sig, input, err := parseJWT(token)
	if err != nil {
		return nil, false, errJWTInvalid
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return nil, false, errJWTInvalid
	}

	key, found := a.jwks.get(kid)
	if !found {
		return nil, false, errUnknownKID
	}
	if err := verifyJWS(header, input, sig, key); err != nil {
		return nil, true, errJWTInvalid
	}

	claims := &tokenClaims{
		RawRolesMap: map[string]any{},
	}
	if err := decodeTokenClaims(payload, claims); err != nil {
		return nil, true, errJWTInvalid
	}
	if err := a.validateTokenClaims(claims); err != nil {
		return nil, true, err
	}
	return claims, true, nil
}

func (a *authContext) validateTokenClaims(c *tokenClaims) error {
	if c.Subject == "" {
		return errJWTInvalid
	}
	if c.Issuer != a.cfg.KeycloakIssuerURL {
		return errJWTInvalid
	}
	if !contains(c.Audience, a.cfg.KeycloakAudience) {
		return errJWTInvalid
	}
	now := time.Now().Unix()
	if c.ExpiresAt <= now || (c.NotBefore != 0 && c.NotBefore > now) {
		return errJWTInvalid
	}
	client := c.AZP
	if client == "" {
		client = c.ClientID
	}
	if client != a.cfg.KeycloakAdminUIClient {
		return errInvalidAdminClient
	}
	if c.CnfJKT == "" {
		return errJWTInvalid
	}
	rolesAny, ok := c.RawRolesMap[a.cfg.KeycloakAudience]
	if !ok {
		return fmt.Errorf("%w %s", errMissingRequiredRole, a.cfg.KeycloakRequiredRole)
	}
	rolesObj, ok := rolesAny.(map[string]any)
	if !ok {
		return fmt.Errorf("%w %s", errMissingRequiredRole, a.cfg.KeycloakRequiredRole)
	}
	rv, ok := rolesObj["roles"].([]any)
	if !ok {
		return fmt.Errorf("%w %s", errMissingRequiredRole, a.cfg.KeycloakRequiredRole)
	}
	hasRole := false
	for _, v := range rv {
		if s, ok := v.(string); ok && s == a.cfg.KeycloakRequiredRole {
			hasRole = true
			break
		}
	}
	if !hasRole {
		return fmt.Errorf("%w %s", errMissingRequiredRole, a.cfg.KeycloakRequiredRole)
	}
	return nil
}

func (a *authContext) validateDPoPProof(r *http.Request, proof, accessToken, expectedJKT string) error {
	header, payload, sig, input, err := parseJWT(proof)
	if err != nil {
		return errDPoPInvalid
	}
	jwkVal, ok := header["jwk"]
	if !ok {
		return errDPoPInvalid
	}
	jwkMap, ok := jwkVal.(map[string]any)
	if !ok {
		return errDPoPInvalid
	}
	pubKey, err := parseJWKPublicKey(jwkMap)
	if err != nil {
		return errDPoPInvalid
	}
	if err := verifyJWS(header, input, sig, pubKey); err != nil {
		return errDPoPInvalid
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return errDPoPInvalid
	}
	if method, _ := claims["htm"].(string); method != r.Method {
		return errDPoPInvalid
	}
	htuExpected, err := a.expectedHTU(r)
	if err != nil {
		return errInvalidConfig
	}
	htuActual, _ := claims["htu"].(string)
	if htuActual != htuExpected {
		return errDPoPHTUMismatch
	}
	iat, ok := numberToInt64(claims["iat"])
	if !ok {
		return errDPoPIatInvalid
	}
	now := time.Now().Unix()
	if iat < now-int64(a.cfg.DPoPProofMaxAgeSeconds)-int64(a.cfg.DPoPClockSkewSeconds) ||
		iat > now+int64(a.cfg.DPoPClockSkewSeconds) {
		return errDPoPIatInvalid
	}
	ath, _ := claims["ath"].(string)
	expectedATH := hashAccessToken(accessToken)
	if ath != expectedATH {
		return errDPoPInvalid
	}
	jti, _ := claims["jti"].(string)
	if strings.TrimSpace(jti) == "" {
		return errDPoPInvalid
	}
	if !a.replay.tryStore(jti) {
		return errDPoPReplay
	}
	jkt, err := jwkThumbprint(jwkMap)
	if err != nil {
		return errDPoPInvalid
	}
	if jkt != expectedJKT {
		return errDPoPJKTMismatch
	}
	return nil
}

func (a *authContext) expectedHTU(r *http.Request) (string, error) {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		return "", errors.New("missing host")
	}
	if a.isTrustedRemote(r.RemoteAddr) {
		if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); v != "" {
			scheme = strings.ToLower(v)
		}
		if v := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); v != "" {
			host = v
		}
		if fp := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); fp != "" {
			h, p, err := net.SplitHostPort(host)
			if err != nil {
				h = host
				p = ""
			}
			if p == "" && ((scheme == "https" && fp != "443") || (scheme == "http" && fp != "80")) {
				host = net.JoinHostPort(h, fp)
			}
		}
	}
	u := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   r.URL.Path,
	}
	return u.String(), nil
}

func (a *authContext) isTrustedRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, c := range a.trustedCIDRs {
		if c.Contains(ip) {
			return true
		}
	}
	return false
}

type jwksCache struct {
	mu         sync.RWMutex
	keys       map[string]any
	lastSyncAt time.Time
	ttl        time.Duration
}

func newJWKSCache(ttl time.Duration) *jwksCache {
	return &jwksCache{keys: map[string]any{}, ttl: ttl}
}

func (j *jwksCache) get(kid string) (any, bool) {
	j.mu.RLock()
	key, ok := j.keys[kid]
	stale := j.lastSyncAt.IsZero() || time.Since(j.lastSyncAt) > j.ttl
	j.mu.RUnlock()
	if ok || !stale {
		return key, ok
	}
	return nil, false
}

func (j *jwksCache) refresh(ctx context.Context, client *http.Client, jwksURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	var payload struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	next := make(map[string]any, len(payload.Keys))
	for _, k := range payload.Keys {
		kid, _ := k["kid"].(string)
		if strings.TrimSpace(kid) == "" {
			continue
		}
		pub, err := parseJWKPublicKey(k)
		if err != nil {
			continue
		}
		next[kid] = pub
	}
	if len(next) == 0 {
		return errors.New("no jwks keys")
	}
	j.mu.Lock()
	j.keys = next
	j.lastSyncAt = time.Now()
	j.mu.Unlock()
	return nil
}

type jtiReplayCache struct {
	mu    sync.Mutex
	items map[string]time.Time
	ttl   time.Duration
}

func newJTIReplayCache(ttl time.Duration) *jtiReplayCache {
	return &jtiReplayCache{
		items: map[string]time.Time{},
		ttl:   ttl,
	}
}

func (c *jtiReplayCache) tryStore(jti string) bool {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.items {
		if now.After(v) {
			delete(c.items, k)
		}
	}
	if exp, ok := c.items[jti]; ok && now.Before(exp) {
		return false
	}
	c.items[jti] = now.Add(c.ttl)
	return true
}

func parseJWT(raw string) (map[string]any, []byte, []byte, []byte, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, nil, nil, errors.New("invalid jwt")
	}
	headBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	var header map[string]any
	if err := json.Unmarshal(headBytes, &header); err != nil {
		return nil, nil, nil, nil, err
	}
	return header, payloadBytes, sig, []byte(parts[0] + "." + parts[1]), nil
}

func verifyJWS(header map[string]any, signedContent, sig []byte, key any) error {
	alg, _ := header["alg"].(string)
	switch alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("invalid key type")
		}
		h := sha256.Sum256(signedContent)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
	case "ES256":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("invalid key type")
		}
		if len(sig) != 64 {
			return errors.New("invalid ecdsa signature size")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		h := sha256.Sum256(signedContent)
		if !ecdsa.Verify(pub, h[:], r, s) {
			return errors.New("invalid ecdsa signature")
		}
		return nil
	default:
		return errors.New("unsupported jwt alg")
	}
}

func parseJWKPublicKey(jwk map[string]any) (any, error) {
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "RSA":
		nS, _ := jwk["n"].(string)
		eS, _ := jwk["e"].(string)
		nB, err := base64.RawURLEncoding.DecodeString(nS)
		if err != nil {
			return nil, err
		}
		eB, err := base64.RawURLEncoding.DecodeString(eS)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(nB)
		e := int(new(big.Int).SetBytes(eB).Int64())
		if e <= 0 {
			return nil, errors.New("invalid exponent")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		crv, _ := jwk["crv"].(string)
		xS, _ := jwk["x"].(string)
		yS, _ := jwk["y"].(string)
		xB, err := base64.RawURLEncoding.DecodeString(xS)
		if err != nil {
			return nil, err
		}
		yB, err := base64.RawURLEncoding.DecodeString(yS)
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch crv {
		case "P-256":
			curve = elliptic.P256()
		default:
			return nil, errors.New("unsupported curve")
		}
		pub := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xB),
			Y:     new(big.Int).SetBytes(yB),
		}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, errors.New("invalid point")
		}
		return pub, nil
	default:
		return nil, errors.New("unsupported kty")
	}
}

func decodeTokenClaims(payload []byte, out *tokenClaims) error {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return err
	}
	if sub, _ := raw["sub"].(string); sub != "" {
		out.Subject = sub
	}
	if iss, _ := raw["iss"].(string); iss != "" {
		out.Issuer = iss
	}
	if audS, ok := raw["aud"].(string); ok && audS != "" {
		out.Audience = []string{audS}
	} else if audArr, ok := raw["aud"].([]any); ok {
		for _, v := range audArr {
			if s, ok := v.(string); ok {
				out.Audience = append(out.Audience, s)
			}
		}
	}
	if exp, ok := numberToInt64(raw["exp"]); ok {
		out.ExpiresAt = exp
	}
	if nbf, ok := numberToInt64(raw["nbf"]); ok {
		out.NotBefore = nbf
	}
	out.AZP, _ = raw["azp"].(string)
	out.ClientID, _ = raw["client_id"].(string)
	if cnf, ok := raw["cnf"].(map[string]any); ok {
		out.CnfJKT, _ = cnf["jkt"].(string)
	}
	if rsrc, ok := raw["resource_access"].(map[string]any); ok {
		out.RawRolesMap = rsrc
	}
	return nil
}

func numberToInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case int64:
		return t, true
	case int:
		return int64(t), true
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}

func contains(s []string, v string) bool {
	for _, it := range s {
		if it == v {
			return true
		}
	}
	return false
}

func hashAccessToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func extractJWTKid(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	headBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var header map[string]any
	if err := json.Unmarshal(headBytes, &header); err != nil {
		return ""
	}
	kid, _ := header["kid"].(string)
	return kid
}

func logAdminAuth(log *logger.Logrus, reason string, r *http.Request, kid string, trustedProxy *bool) {
	l := log.
		WithField("reason", reason).
		WithField("method", r.Method).
		WithField("path", r.URL.Path).
		WithField("remote_addr", r.RemoteAddr).
		WithField("request_id", requestIDFromCtx(r))
	if kid != "" {
		l = l.WithField("kid", kid)
	}
	if trustedProxy != nil {
		l = l.WithField("trusted_proxy", *trustedProxy)
	}
	l.Infof("admin_auth")
}

func jwkThumbprint(jwk map[string]any) (string, error) {
	kty, _ := jwk["kty"].(string)
	var canonical string
	switch kty {
	case "RSA":
		e, _ := jwk["e"].(string)
		n, _ := jwk["n"].(string)
		if e == "" || n == "" {
			return "", errors.New("invalid rsa jwk")
		}
		canonical = `{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`
	case "EC":
		crv, _ := jwk["crv"].(string)
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		if crv == "" || x == "" || y == "" {
			return "", errors.New("invalid ec jwk")
		}
		canonical = `{"crv":"` + crv + `","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	default:
		return "", errors.New("unsupported kty")
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}
