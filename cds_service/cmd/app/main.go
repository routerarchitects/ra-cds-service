/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package main

import (
	"log"
	"net/http"

	"cds/internal/app"
	"cds/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}

	a, err := app.Init(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer a.DB.Close()

	log.Printf("CDS unified API listening on %s", cfg.HTTPAddr)
	log.Fatal(http.ListenAndServe(cfg.HTTPAddr, a.Mux))
}
