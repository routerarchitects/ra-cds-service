/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package app

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"cds/internal/adapters/logger"
	"cds/internal/adapters/postgres"
	"cds/internal/config"
	httpx "cds/internal/http"
	"cds/internal/services"

	_ "github.com/lib/pq"
)

type App struct {
	DB  *sql.DB
	Mux *http.ServeMux
}

func pingWithRetry(db *sql.DB, attempts int, delay time.Duration) error {
	var err error
	for i := 1; i <= attempts; i++ {
		err = db.Ping()
		if err == nil {
			return nil
		}
		time.Sleep(delay)
	}
	return errors.New("database not reachable after retries: " + err.Error())
}

func Init(cfg *config.Config) (*App, error) {
	log := logger.New()

	db, err := sql.Open("postgres", cfg.PostgresDSN)
	if err != nil {
		return nil, err
	}
	if err := pingWithRetry(db, 60, 500*time.Millisecond); err != nil {
		return nil, err
	}

	repo := postgres.NewRepo(db)
	svc := services.New(repo)

	mux := httpx.NewRouterWithConfig(cfg, svc)

	log.Infof("Initialized CDS service")
	return &App{DB: db, Mux: mux}, nil
}

