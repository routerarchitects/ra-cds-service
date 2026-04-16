/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package services

import (
	"context"

	"cds/internal/adapters/postgres"
)

type DeviceService struct {
	repo *postgres.Repo
}

func New(repo *postgres.Repo) *DeviceService { return &DeviceService{repo: repo} }

// Device-facing
func (s *DeviceService) Lookup(serial string) (string, error) {
	return s.repo.GetEndpointBySerial(context.Background(), serial)
}

// Admin-facing (scoped by owner token)
func (s *DeviceService) AddOwned(serial, controllerEndpoint, owner string) error {
	return s.repo.AddDevice(context.Background(), serial, controllerEndpoint, owner)
}
func (s *DeviceService) UpdateOwned(serial, controllerEndpoint, owner string) error {
	return s.repo.UpdateDevice(context.Background(), serial, controllerEndpoint, owner)
}
func (s *DeviceService) DeleteOwned(serial, owner string) error {
	return s.repo.DeleteDevice(context.Background(), serial, owner)
}
func (s *DeviceService) ListByOwner(owner string) ([]map[string]string, error) {
	return s.repo.ListDevicesByOwner(context.Background(), owner)
}

