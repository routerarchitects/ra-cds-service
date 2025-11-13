## ra-cds-service

A Dockerized CDS (Controller Discovery Service) for storing and serving device → controller endpoint mappings.
This service runs Go APIs (PostgreSQL-backed) fronted by Nginx (TLS).

## Table of Contents

-   [Overview](#overview)

-   [Prerequisites](#prerequisites)

-   [Clone](#clone)

-   [Local Development (Quick Start)](#local-development-quick-start)

-   [Generate & Place Server Certificates](#generateplace-server-certificate)

-   [Run (Docker-Compose)](#run-docker-compose)

-   [Verify](#verify)

-   [Troubleshooting](#troubleshooting)

-   [License](#license)

----------

## Overview

`ra-cds-service` exposes HTTPS APIs to:

-   Add / update / delete /list devices.
-   Serves the device → controller endpoint mappings.


**You will:**

-  **Build/run** containers(Postgres + CDS service + Nginx TLS) with Docker Compose.


## Prerequisites

-   Docker Engine and Docker Compose (v2):  `docker --version`,  `docker compose version`
-   OpenSSL (for certificate generation)

----------

## Clone

```
git clone https://github.com/routerarchitects/ra-cds-service.git
cd ra-cds-service
```

**Expected minimal service structure (After clone):**
```
ra-cds-service/cds_service/
├── cmd/app/main.go
├── Dockerfile
├── go.mod
└── internal/
    ├── adapters/logger/logrus_logger.go
    ├── adapters/postgres/devices_repo.go
    ├── app/app.go
    ├── config/config.go
    ├── http/handlers_devices.go
    ├── http/middleware.go
    └── http/routes.go
```
----------

## Local Development (Quick Start)

**Create the deployment folder and files:**

```
mkdir -p cds_deploy/{db,nginx/certs}
```

### Root layout of service(expected) :

```
ra-cds-service/
   ├── cds_service/   # Go service (cloned from Git repo)
   └── cds_deploy/    # Deployment assets: Postgres, Nginx (TLS), docker-compose
 ```

----------

Copy the **complete** contents below into the respective files.

### `cds_deploy/docker-compose.yml`

```
services:
  postgres:
    image: postgres:16-alpine
    container_name: cds-postgres
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
      POSTGRES_DB: cds
    volumes:
      - ./db/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d cds || exit 1"]
      interval: 2s
      timeout: 2s
      retries: 30
      start_period: 5s
    restart: unless-stopped

  cds-api:
    build:
      context: ../cds_service
      dockerfile: Dockerfile
    container_name: cds-api
    ports:
      - "8080:8080"
    env_file:
      - .env
    depends_on:
      postgres:
        condition: service_healthy
    healthcheck:
      test: ["CMD-SHELL", "curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1 || exit 1"]
      interval: 2s
      timeout: 2s
      retries: 30
      start_period: 5s
    restart: unless-stopped

  nginx:
    build:
      context: ./nginx
    container_name: cds-nginx
    ports:
      - "4443:4443"
      - "5443:5443"
    depends_on:
      cds-api:
        condition: service_healthy
    restart: unless-stopped

  ```

### `cds_deploy/db/init.sql`

```sql
CREATE TABLE IF NOT EXISTS public.devices (
  serial TEXT PRIMARY KEY,
  controller_endpoint TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  owner_token TEXT
);

-- Lowercase serial
CREATE OR REPLACE FUNCTION trg_lower_serial()
RETURNS TRIGGER AS $$
BEGIN
  NEW.serial := lower(NEW.serial);
  RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS lower_serial_on_devices ON public.devices;
CREATE TRIGGER lower_serial_on_devices
BEFORE INSERT OR UPDATE ON public.devices
FOR EACH ROW EXECUTE PROCEDURE trg_lower_serial();

-- Maintain updated_at
CREATE OR REPLACE FUNCTION trg_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_updated_at ON public.devices;
CREATE TRIGGER set_updated_at
BEFORE UPDATE ON public.devices
FOR EACH ROW EXECUTE PROCEDURE trg_set_updated_at();

-- Ensure column exists if old DB (idempotent)
ALTER TABLE public.devices
  ADD COLUMN IF NOT EXISTS owner_token TEXT;
```

### `cds_deploy/nginx/Dockerfile`

```
FROM nginx:1.27-alpine
COPY cds.conf /etc/nginx/conf.d/default.conf
COPY certs/server-cert.pem /etc/ssl/certs/server-cert.pem
COPY certs/server-key.pem /etc/ssl/private/server-key.pem
COPY certs/cacerts.pem /etc/ssl/certs/ca-cert.pem
EXPOSE 4443 5443
```

### `cds_deploy/nginx/cds.conf`

```# Device-facing API (requires mTLS)
server {
    listen 4443 ssl;
    server_name localhost;

    ssl_certificate        /etc/ssl/certs/server-cert.pem;
    ssl_certificate_key    /etc/ssl/private/server-key.pem;
    ssl_client_certificate /etc/ssl/certs/ca-cert.pem;
    ssl_verify_client      on;

    location /v1/devices/ {
        proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
        proxy_pass http://cds-api:8080;
    }
}

# Admin-facing API (no client cert)
server {
    listen 5443 ssl;
    server_name localhost;

    ssl_certificate        /etc/ssl/certs/server-cert.pem;
    ssl_certificate_key    /etc/ssl/private/server-key.pem;
    ssl_verify_client      off;

    location /v1/device/ {
        proxy_pass http://cds-api:8080;
    }
}
```
### `cds_deploy/.env`

```
# PostgreSQL DSN for unified cds_service
POSTGRES_DSN=postgres://postgres:password@postgres:5432/cds?sslmode=disable

# Go service listen address (must match EXPOSE 8080)
HTTP_ADDR=:8080

# Url to validate security token
VALIDATE_TOKEN_URL=https://openwifi3.routerarchitects.com:16001/api/v1/validateToken
```
---------

**Note:**
 Set VALIDATE_TOKEN_URL to the exact token-validation endpoint of your deployment(If any).
The CDS service will call this URL to verify that the provided security-Token is valid.

## Generate & Place Server Certificates

**Important:**
 The Nginx **server certificate must be issued by the same CA & issuer that signs the devices operational certificates**, so devices/clients can trust this service.

> **Where to place:** `cds_deploy/nginx/certs/{server-cert.pem,server-key.pem,cacerts.pem}`

**Expected Layout for cds_deploy/**
**tree cds_deploy -a**
```
cds_deploy/
├── db/init.sql
├── docker-compose.yml
|── .env
└── nginx/
    ├── Dockerfile
    ├── cds.conf
    └── certs/
        ├── cacerts.pem
        ├── server-cert.pem
        └── server-key.pem
```
----------



## Run (Docker-Compose)

```cd ra-cds-service/cds_deploy
docker-compose build
docker-compose up -d
```

**To see Logs:**

```
docker-compose logs -f postgres
docker-compose logs -f cds_service
docker-compose logs -f nginx
```

----------

## Verify

### Important Note(Security Token Requirement):
- The CDS service enforces strict access control.
- All **add / update / delete / list** operations require a valid security-token belonging to a user with the **root** role.
- Always make sure you are using a valid root security-token before running any admin operations.


### Add device

```
curl -k -X POST https://localhost:5443/v1/device/add \
  -H "X-Auth-Token: <use valid root security-token here>" \
  -H "Content-Type: application/json" \
  -d '{"serial":"<device-serial-no.>", "controller_endpoint":"<controller-url>"}'

Ex:
curl -k -X POST https://localhost:5443/v1/device/add \
  -H "X-Auth-Token: 7889ca8f760184f2dd0841a32c70351eec9331d16af88932fbe824352a16717f" \
  -H "Content-Type: application/json" \
  -d '{"serial":"b4:6a:d4:45:f0:19", "controller_endpoint":"openwifi1.routerarchitects.com"}'
```

### Update device

```
curl -k -X PUT https://localhost:5443/v1/device/update \
  -H "X-Auth-Token: 7889ca8f760184f2dd0841a32c70351eec9331d16af88932fbe824352a16717f" \
  -H "Content-Type: application/json" \
  -d '{"serial":"b4:6a:d4:45:f0:19", "controller_endpoint":"openwifi3.routerarchitects.com"}'
  ```

### Delete device

```
curl -k -X DELETE https://localhost:5443/v1/device/delete \
  -H "X-Auth-Token: 7889ca8f760184f2dd0841a32c70351eec9331d16af88932fbe824352a16717f" \
  -H "Content-Type: application/json" \
  -d '{"serial":"b4:6a:d4:45:f0:19"}'
```

### List all devices (Added with security token)

```
curl -k https://localhost:5443/v1/device/list \
  -H "X-Auth-Token: 7889ca8f760184f2dd0841a32c70351eec9331d16af88932fbe824352a16717f"
```

### Get controller url from device serial no.(Use device operational certs for mTLS)

```
curl -k https://localhost:4443/v1/devices/b4:6a:d4:45:f0:19 \
  --cacert operational.ca \
  --cert   operational.pem \
  --key    key.pem
  ```

### To test service through device(AP)
**Ensure the following:**
- Device firmware version: must be 4.1.0 or later
- Device should have operational certs signed by same CA & Issuer as
  cds-server certificates.
- Ensure the file /etc/ucentral/gateway.json does not exist on the device
- Update the CDS URL inside /usr/bin/cloud_discovery to point to your
  deployed CDS service
- Restart cloud discovery agent:
  `/etc/init.d/cloud_rescovery restart`
**Expected Behaviour:**
Respose will be store in gateway.json if already there is entry for device
serial no.in db with a valid security token.
----------


## Troubleshooting

-   **Handshake / chain errors**
    Ensure `server-cert.pem` matches `server-key.pem`, and `cacerts.pem` is the correct CA chain (same issuer as device operational certs). Check URL SAN vs hostname.

-   **Permission errors**
    Verify Docker can read the certs/keys in `nginx/certs` and the bind mounts exist.

-   **Wrong port**
    Local tests assume `"5443:4443"`.If you changes ports,update curl commands accordingly.

-   **Schema mismatch**
    Align `init.sql` with what `internal/adapters/postgres/devices_repo.go` expects.


----------

## License
- SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
 - Copyright (c) 2025 Infernet Systems Pvt Ltd

