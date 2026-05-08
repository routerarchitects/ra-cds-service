/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"net/http"

	"cds/internal/config"
	"cds/internal/services"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func NewRouterWithConfig(cfg *config.Config, svc *services.DeviceService) http.Handler {
	h := NewDeviceHandler(svc)
	mux := http.NewServeMux()

	// Health (no auth)
	mux.HandleFunc("GET /health", healthHandler)

	// Device (mTLS) route
	mux.Handle("GET /v1/devices/{serial}", RequireClientCert(cfg, http.HandlerFunc(h.LookupBySerial)))

	// Admin routes (Keycloak DPoP)
	admin := func(hh http.HandlerFunc) http.Handler { return RequireKeycloakDPoPAdmin(cfg, hh) }
	mux.Handle("POST /v1/device", admin(http.HandlerFunc(h.Add)))
	mux.Handle("PUT /v1/device", admin(http.HandlerFunc(h.Update)))
	mux.Handle("DELETE /v1/device/{serial}", admin(http.HandlerFunc(h.Delete)))
	mux.Handle("GET /v1/device", admin(http.HandlerFunc(h.List)))

	return AccessLogger(mux)
}
