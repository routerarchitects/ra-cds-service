/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
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

var adminDeviceSerialPattern = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

func normalizeAdminDeviceSerial(serial string) (string, bool) {
	serial = strings.TrimSpace(serial)
	return serial, adminDeviceSerialPattern.MatchString(serial)
}

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
	serial, valid := normalizeAdminDeviceSerial(req.Serial)
	req.Serial = serial

	ownerScope, err := GetOwnerScopeFromCtx(r)
	if err != nil {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	if !valid {
		http.Error(w, "serial is missing, empty, or does not match lowercase MAC-style format aa:bb:cc:dd:ee:ff", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ControllerEndpoint) == "" {
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
	serial, valid := normalizeAdminDeviceSerial(req.Serial)
	req.Serial = serial

	ownerScope, err := GetOwnerScopeFromCtx(r)
	if err != nil {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	if !valid {
		http.Error(w, "serial is missing, empty, or does not match lowercase MAC-style format aa:bb:cc:dd:ee:ff", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ControllerEndpoint) == "" {
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
	serial, valid := normalizeAdminDeviceSerial(r.PathValue("serial"))

	ownerScope, err := GetOwnerScopeFromCtx(r)
	if err != nil {
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	if !valid {
		http.Error(w, "serial path parameter is missing, empty, or does not match lowercase MAC-style format aa:bb:cc:dd:ee:ff", http.StatusBadRequest)
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
