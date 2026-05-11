/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"cds/internal/adapters/postgres"
	"cds/internal/services"
)

type DeviceHandler struct {
	svc *services.DeviceService
}

func NewDeviceHandler(svc *services.DeviceService) *DeviceHandler {
	return &DeviceHandler{svc: svc}
}

// -------- Device-facing (mTLS) -----------
// GET /v1/devices/{serial}
func (h *DeviceHandler) LookupBySerial(w http.ResponseWriter, r *http.Request) {
	serial := strings.ToLower(strings.TrimSpace(r.PathValue("serial")))
	if serial == "" {
		http.Error(w, "serial required", http.StatusBadRequest)
		return
	}

	controllerEndpoint, err := h.svc.Lookup(serial)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"serial":              serial,
		"controller_endpoint": controllerEndpoint,
	})
}

// -------------- Admin (Keycloak DPoP) ----------------

type addReq struct {
	Serial             string `json:"serial"`
	ControllerEndpoint string `json:"controller_endpoint"`
}
type updateReq struct {
	Serial             string `json:"serial"`
	ControllerEndpoint string `json:"controller_endpoint"`
}

const maxAdminRequestBodyBytes int64 = 1 << 20 // 1 MiB

// POST /v1/device
func (h *DeviceHandler) Add(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	var req addReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Serial = strings.ToLower(strings.TrimSpace(req.Serial))

	ownerScope, err := GetOwnerScopeFromCtx(r)
	if err != nil {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	if req.Serial == "" || strings.TrimSpace(req.ControllerEndpoint) == "" {
		http.Error(w, "serial and controller_endpoint are required", http.StatusBadRequest)
		return
	}

	if err := h.svc.AddOwned(req.Serial, req.ControllerEndpoint, ownerScope); err != nil {
		if errors.Is(err, postgres.ErrDeviceOwnerConflict) {
			http.Error(w, "device already exists for another owner", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// PUT /v1/device
func (h *DeviceHandler) Update(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	var req updateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Serial = strings.ToLower(strings.TrimSpace(req.Serial))

	ownerScope, err := GetOwnerScopeFromCtx(r)
	if err != nil {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	if req.Serial == "" || strings.TrimSpace(req.ControllerEndpoint) == "" {
		http.Error(w, "serial and controller_endpoint are required", http.StatusBadRequest)
		return
	}

	if err := h.svc.UpdateOwned(req.Serial, req.ControllerEndpoint, ownerScope); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// DELETE /v1/device/{serial}
func (h *DeviceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	serial := strings.ToLower(strings.TrimSpace(r.PathValue("serial")))

	ownerScope, err := GetOwnerScopeFromCtx(r)
	if err != nil {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	if serial == "" {
		http.Error(w, "serial path parameter is empty or whitespace after trimming", http.StatusBadRequest)
		return
	}

	if err := h.svc.DeleteOwned(serial, ownerScope); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /v1/device
func (h *DeviceHandler) List(w http.ResponseWriter, r *http.Request) {
	ownerScope, err := GetOwnerScopeFromCtx(r)
	if err != nil {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	devices, err := h.svc.ListByOwner(ownerScope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(devices)
}
