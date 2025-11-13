/*
 * SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 * Copyright (c) 2025 Infernet Systems Pvt Ltd
 */
package postgres

import (
	"context"
	"database/sql"
	"errors"
)

type Repo struct{ db *sql.DB }

func NewRepo(db *sql.DB) *Repo { return &Repo{db: db} }

// Device-facing lookup (no owner check)
func (r *Repo) GetEndpointBySerial(ctx context.Context, serial string) (string, error) {
	var controllerEndpoint string
	err := r.db.QueryRowContext(ctx,
		`SELECT controller_endpoint FROM public.devices WHERE serial=$1`, serial).
		Scan(&controllerEndpoint)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", sql.ErrNoRows
		}
		return "", err
	}
	return controllerEndpoint, nil
}

// Admin-facing (scoped to owner token)
func (r *Repo) AddDevice(ctx context.Context, serial, controllerEndpoint, owner string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO public.devices (serial, controller_endpoint, owner_token)
         VALUES (lower($1), $2, $3)
         ON CONFLICT (serial) DO UPDATE
           SET controller_endpoint = EXCLUDED.controller_endpoint,
               owner_token = EXCLUDED.owner_token`,
		serial, controllerEndpoint, owner)
	return err
}

func (r *Repo) UpdateDevice(ctx context.Context, serial, controllerEndpoint, owner string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE public.devices
           SET controller_endpoint=$2
         WHERE serial=lower($1) AND owner_token=$3`,
		serial, controllerEndpoint, owner)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *Repo) DeleteDevice(ctx context.Context, serial, owner string) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM public.devices WHERE serial=lower($1) AND owner_token=$2`,
		serial, owner)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *Repo) ListDevicesByOwner(ctx context.Context, owner string) ([]map[string]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT serial, controller_endpoint
           FROM public.devices
          WHERE owner_token=$1
          ORDER BY serial ASC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []map[string]string
	for rows.Next() {
		var s, ce string
		if err := rows.Scan(&s, &ce); err != nil {
			return nil, err
		}
		res = append(res, map[string]string{
			"serial":              s,
			"controller_endpoint": ce,
		})
	}
	return res, rows.Err()
}

