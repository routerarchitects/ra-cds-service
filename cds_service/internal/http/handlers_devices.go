/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"encoding/json"
	"net/http"
	"strings"

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
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/devices/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "serial required", http.StatusBadRequest)
		return
	}
	serial := strings.ToLower(parts[0])

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

// -------------- Admin (validated token, userRole=root) ----------------

type addReq struct {
	Serial             string `json:"serial"`
	ControllerEndpoint string `json:"controller_endpoint"`
}
type updateReq struct {
	Serial             string `json:"serial"`
	ControllerEndpoint string `json:"controller_endpoint"`
}
type deleteReq struct {
	Serial string `json:"serial"`
}

// POST /v1/device/add
func (h *DeviceHandler) Add(w http.ResponseWriter, r *http.Request) {
	var req addReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Serial = strings.ToLower(strings.TrimSpace(req.Serial))

	ownerToken, err := GetOwnerTokenFromCtx(r)
	if err != nil {
		http.Error(w, "security token validation failed", http.StatusForbidden)
		return
	}
	if req.Serial == "" || strings.TrimSpace(req.ControllerEndpoint) == "" {
		http.Error(w, "serial and controller_endpoint are required", http.StatusBadRequest)
		return
	}

	if err := h.svc.AddOwned(req.Serial, req.ControllerEndpoint, ownerToken); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// POST /v1/device/update
func (h *DeviceHandler) Update(w http.ResponseWriter, r *http.Request) {
	var req updateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Serial = strings.ToLower(strings.TrimSpace(req.Serial))

	ownerToken, err := GetOwnerTokenFromCtx(r)
	if err != nil {
		http.Error(w, "security token validation failed", http.StatusForbidden)
		return
	}
	if req.Serial == "" || strings.TrimSpace(req.ControllerEndpoint) == "" {
		http.Error(w, "serial and controller_endpoint are required", http.StatusBadRequest)
		return
	}

	if err := h.svc.UpdateOwned(req.Serial, req.ControllerEndpoint, ownerToken); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /v1/device/delete
func (h *DeviceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	var req deleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Serial = strings.ToLower(strings.TrimSpace(req.Serial))

	ownerToken, err := GetOwnerTokenFromCtx(r)
	if err != nil {
		http.Error(w, "security token validation failed", http.StatusForbidden)
		return
	}
	if req.Serial == "" {
		http.Error(w, "serial is required", http.StatusBadRequest)
		return
	}

	if err := h.svc.DeleteOwned(req.Serial, ownerToken); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /v1/device/list
func (h *DeviceHandler) List(w http.ResponseWriter, r *http.Request) {
	ownerToken, err := GetOwnerTokenFromCtx(r)
	if err != nil {
		http.Error(w, "security token validation failed", http.StatusForbidden)
		return
	}
	devices, err := h.svc.ListByOwner(ownerToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(devices)
}

