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

func NewRouterWithConfig(cfg *config.Config, svc *services.DeviceService) *http.ServeMux {
	h := NewDeviceHandler(svc)
	mux := http.NewServeMux()

	// Health (no auth)
	mux.HandleFunc("/health", healthHandler)

	// Device (mTLS) route — unchanged
	mux.Handle("/v1/devices/", RequireClientCert(http.HandlerFunc(h.LookupBySerial)))

	// Admin routes (validated token, userRole==root)
	admin := func(hh http.HandlerFunc) http.Handler { return RequireValidatedAdmin(cfg, hh) }
	mux.Handle("/v1/device/add",    admin(http.HandlerFunc(h.Add)))
	mux.Handle("/v1/device/update", admin(http.HandlerFunc(h.Update)))
	mux.Handle("/v1/device/delete", admin(http.HandlerFunc(h.Delete)))
	mux.Handle("/v1/device/list",   admin(http.HandlerFunc(h.List)))

	return mux
}

