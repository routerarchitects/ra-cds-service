/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"cds/internal/adapters/logger"
)

type accessCtxKey string

const ctxKeyRequestID accessCtxKey = "requestID"

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(b)
}

func AccessLogger(next http.Handler) http.Handler {
	log := logger.New()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
		if requestID == "" {
			requestID = generateRequestID()
		}
		w.Header().Set("X-Request-Id", requestID)

		ctx := context.WithValue(r.Context(), ctxKeyRequestID, requestID)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(ctx))

		log.
			WithField("method", r.Method).
			WithField("path", r.URL.Path).
			WithField("status", rec.status).
			WithField("latency_ms", time.Since(start).Milliseconds()).
			WithField("remote_addr", r.RemoteAddr).
			WithField("request_id", requestID).
			Infof("http_access")
	})
}

func generateRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-id-unavailable"
	}
	return hex.EncodeToString(b[:])
}

func requestIDFromCtx(r *http.Request) string {
	v := r.Context().Value(ctxKeyRequestID)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
