/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package config

import (
	"fmt"
	"os"
)

type Config struct {
	PostgresDSN      string
	HTTPAddr         string
	ValidateTokenURL string
}

func Load() (*Config, error) {
	cfg := &Config{
		PostgresDSN:      os.Getenv("POSTGRES_DSN"),
		HTTPAddr:         os.Getenv("HTTP_ADDR"),
		ValidateTokenURL: os.Getenv("VALIDATE_TOKEN_URL"),
	}

	if cfg.PostgresDSN == "" {
		cfg.PostgresDSN = "postgres://postgres:password@postgres:5432/cds?sslmode=disable"
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = ":8080"
	}
	if cfg.ValidateTokenURL == "" {
		return nil, fmt.Errorf("VALIDATE_TOKEN_URL is required")
	}
	return cfg, nil
}

