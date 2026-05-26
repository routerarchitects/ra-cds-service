# ra-cds-service

Dockerized CDS (Controller Discovery Service) deployment for storing and serving device-to-controller endpoint mappings.

This repository contains:

- `cds_service/` — Go backend service.
- `cds_deploy/` — Docker Compose deployment assets for:
  - PostgreSQL
  - Keycloak
  - CDS backend API
  - Nginx TLS reverse proxy
  - Admin UI static hosting

The CDS deployment supports:

- Admin UI with Keycloak login and DPoP-bound access tokens.
- Admin APIs protected by Keycloak DPoP authentication.
- Device-facing mTLS lookup API.
- PostgreSQL-backed device serial to controller endpoint mappings.

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Clone Repositories](#clone-repositories)
- [Deployment Files](#deployment-files)
- [Build Admin UI](#build-admin-ui)
- [Configure TLS Certificates](#configure-tls-certificates)
- [Configure Backend Environment](#configure-backend-environment)
- [Configuration cds_deploy/nginx/cds.conf](#configuration-cds_deploynginxcdsconf)
- [Start Containers](#start-containers)
- [Configure Keycloak](#configure-keycloak)
- [Verify Deployment](#verify-deployment)
- [Test Admin UI Flow](#test-admin-ui-flow)
- [Test Device mTLS Lookup](#test-device-mtls-lookup)
- [Cloud Firewall / Security Group](#cloud-firewall--security-group)
- [Troubleshooting](#troubleshooting)
- [Security Notes](#security-notes)
- [Expected Successful Result](#expected-successful-result)
- [License](#license)

---

## Architecture

The deployment runs four containers. The Admin UI is served statically by the nginx container.

| Component | Container | Purpose |
|---|---|---|
| PostgreSQL | `cds-postgres` | Stores CDS device mappings and Keycloak data |
| Keycloak | `cds-keycloak` | Issues DPoP-bound access tokens for Admin UI |
| CDS API | `cds-api` | Go backend service |
| Nginx | `cds-nginx` | TLS reverse proxy, Admin UI static hosting, mTLS frontend |

Default external routes:

| Route | Purpose |
|---|---|
| `https://cds.example.com:5443/` | CDS Admin UI |
| `https://cds.example.com:5443/keycloak/admin` | Keycloak Admin Console |
| `https://cds.example.com:5443/keycloak/realms/cds` | Keycloak issuer |
| `https://cds.example.com:5443/keycloak/realms/cds/protocol/openid-connect/certs` | Keycloak JWKS URL |
| `https://cds.example.com:5443/v1/device` | Admin device API |
| `https://cds.example.com:4443/v1/devices/{serial}` | Device-facing mTLS lookup API |

Replace `cds.example.com` with the real DNS name for your deployment.

---


## Prerequisites

Install the following on the deployment host:

- Git
- Docker Engine
- Docker Compose v2
- OpenSSL
- Node.js 20.19+ or 22.12+
- npm

Check versions:

```bash
git --version
docker --version
docker compose version
openssl version
node -v
npm -v
```

The Admin UI uses Vite. Node.js 18 is not sufficient for newer Vite versions. Use Node.js 20.19+ or 22.12+.

If Node.js is too old, install Node.js 20:

```bash
sudo apt remove -y nodejs npm
sudo apt update
sudo apt install -y curl ca-certificates gnupg

curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

node -v
npm -v
```

---

## Clone Repositories

Create the workspace:

```bash
mkdir -p ~/cds_workspace
cd ~/cds_workspace
```

Clone the backend service:

```bash
git clone https://github.com/routerarchitects/ra-cds-service.git
```

Clone the Admin UI repository:

```bash
git clone https://github.com/routerarchitects/mc-cds-ui.git
```

Expected directory structure:


```text
~/cds_workspace/
├── mc-cds-ui/
│   ├── cds-admin-ui/
│   └── ui-spec/
└── ra-cds-service/
    ├── cds_service/
    └── cds_deploy/
```

---

## Deployment Files

The deployment files are already included in this repository under `cds_deploy/`.

The examples in this repository use `cds.example.com`. Replace this with your actual deployment DNS name.

Main files to review and update:

| File | What to update |
|---|---|
| `cds_deploy/.env.example` | Deployers copy `.env.example` to `.env` and update deployment-specific values.|
| `cds_deploy/docker-compose.yml` | Keycloak hostname, DB credentials, UI dist mount path, Docker subnet |
| `cds_deploy/nginx/cds.conf` | Public server name, Nginx routes, TLS certificate paths |
| `cds_deploy/nginx/Dockerfile` | Nginx base image and config only; TLS certs/keys are mounted at runtime |
| `mc-cds-ui/cds-admin-ui/.env` | Admin UI Keycloak and API settings |

Update these deployment files with below guidance.

---

## Build Admin UI

The Admin UI is served by the `cds-nginx` container from the built `dist/` directory.

Go to the Admin UI project:

```bash
cd ~/cds_workspace/mc-cds-ui/cds-admin-ui
```

Create the local Admin UI environment file from the example:

```
cp .env.example .env
```


Update this value:

```text
VITE_KEYCLOAK_ISSUER=https://auth.example.com/realms/cds
```

Use your actual deployment hostname.

Example:

```text
VITE_KEYCLOAK_ISSUER=https://openwifi.routerarchitects.com:5443/keycloak/realms/cds
```

Install dependencies and build:

```bash
rm -rf node_modules package-lock.json
npm install --no-audit --no-fund
npm run build
```

Verify output:

```bash
ls -la dist/
```

Expected output includes:

```text
index.html
assets/
```

---

## Configure TLS Certificates

Nginx serves two HTTPS ports:

| Port | Purpose | Client certificate required |
|---|---|---|
| `5443` | Admin UI, Keycloak, Admin API | No |
| `4443` | Device-facing lookup API | Yes, mTLS |

Place certificates under:

```text
~/cds_workspace/ra-cds-service/cds_deploy/nginx/certs/
```

These certificate and key files are mounted into the Nginx container at runtime by `docker-compose.yml`.

Expected files:

```text
admin-server-cert.pem
admin-server-key.pem
device-server-cert.pem
device-server-key.pem
device-client-ca.pem
```

### Certificates purpose

| File | Purpose |
|---|---|
| `admin-server-cert.pem` | Public TLS certificate for Admin UI, Keycloak, and Admin API on port `5443` |
| `admin-server-key.pem` | Private key for `admin-server-cert.pem` |
| `device-server-cert.pem` | Server TLS certificate for the device-facing mTLS API on port `4443` |
| `device-server-key.pem` | Private key for `device-server-cert.pem` |
| `device-client-ca.pem` | CA chain used by Nginx to verify device client certificates on port `4443` |

For the device-facing mTLS API, `device-server-cert.pem`, `device-server-key.pem`, and `device-client-ca.pem` must align with the CA/issuer used for actual device operational certificates. Devices use this CA chain to trust the CDS server, and Nginx uses `device-client-ca.pem` to verify device client certificates.

For the Admin UI, Keycloak, and Admin API, `admin-server-cert.pem` and `admin-server-key.pem` should be REST API HTTPS server certificates for the public deployment hostname. The admin certificate must include the actual hostname in its SAN, for example:

```text
DNS.1 = openwifi.routerarchitects.com
```

## Configure Backend Environment

The deployment ships with an example environment file:

```text
cds_deploy/.env.example
```
Create the local deployment environment file from the example:

```
cd ~/cds_workspace/ra-cds-service/cds_deploy
cp .env.example .env
```
Update the placeholder host cds.example.com with your actual deployment hostname in `.env`.
Also set strong values for `POSTGRES_PASSWORD` and `KEYCLOAK_ADMIN_PASSWORD` before first startup.

For example, change:
```
KC_HOSTNAME=https://cds.example.com:5443/keycloak
KEYCLOAK_ISSUER_URL=https://cds.example.com:5443/keycloak/realms/cds
KEYCLOAK_JWKS_URL=https://cds.example.com:5443/keycloak/realms/cds/protocol/openid-connect/certs
```
To (Update with your actual DNS):
```
KC_HOSTNAME=https://openwifi.routerarchitects.com:5443/keycloak
KEYCLOAK_ISSUER_URL=https://openwifi.routerarchitects.com:5443/keycloak/realms/cds
KEYCLOAK_JWKS_URL=https://openwifi.routerarchitects.com:5443/keycloak/realms/cds/protocol/openid-connect/certs
```

Admin UI must use the same host in `mc-cds-ui/cds-admin-ui/.env`:

```env
VITE_KEYCLOAK_ISSUER=https://<real-host>:5443/keycloak/realms/cds
```

## Configuration cds_deploy/nginx/cds.conf

Before deployment, replace ```cds.example.com``` with your actual DNS:

Example:

```text
server_name  cds.example.com;
```

replace with your actual deployment DNS name like:

```text
server_name  openwifi.routerarchitects.com;
```

Update `server_name` in both server blocks (port `4443` and port `5443`).

---

## Start Containers

Go to the deployment directory:

```bash
cd ~/cds_workspace/ra-cds-service/cds_deploy
```

Validate Compose configuration:

```bash
docker compose config
```

Build and start:

```bash
docker compose build
docker compose up -d
```


Check containers:

```bash
docker ps -a | grep cds
```

Expected containers:

```text
cds-postgres
cds-keycloak
cds-api
cds-nginx
```

Check logs:

```bash
docker compose logs -f postgres
docker compose logs -f keycloak
docker compose logs -f cds-api
docker compose logs -f nginx
```

Verify Nginx active config:

```bash
docker exec -it cds-nginx nginx -T | grep -E "listen|server_name" -n
```

Expected:

```text
listen 4443 ssl;
listen 5443 ssl;
server_name cds.example.com;
```

with your actual hostname.

---

## Configure Keycloak

Open the Keycloak Admin Console:

```text
https://cds.example.com:5443/keycloak/admin
```

Login using the bootstrap admin credentials from `docker-compose.yml`.

Example:

```text
username: admin 
password: admin
```

Change the admin password for any real deployment.

---

### Create Realm

Create a realm named:

```text
cds
```

All clients, roles, and users below should be created inside the `cds` realm.

---

### Create Backend Audience Client: `cds-service`

Create an OpenID Connect client:

| Field | Value |
|---|---|
| Client ID | `cds-service` |
| Name | `CDS Service` |

Recommended settings:

| Setting | Value |
|---|---|
| Client authentication | Off |
| Authorization | Off |
| Standard flow | Off |
| Direct access grants | Off |
| Implicit flow | Off |
| Device Authorization Grant | Off |

Save the client.

Create a client role under `cds-service`:

```text
cds-admin
```

---

### Create Admin UI Client: `cds-admin-ui`

Create an OpenID Connect client:

| Field | Value |
|---|---|
| Client ID | `cds-admin-ui` |
| Name | `CDS Admin UI` |

Recommended settings:

| Setting | Value |
|---|---|
| Client authentication | Off |
| Authorization | Off |
| Standard flow | On |
| Direct access grants | Off |
| Implicit flow | Off |
| Device Authorization Grant | Off |

Set URLs using your deployment host.

For placeholder host:

| Field | Value |
|---|---|
| Root URL | `https://cds.example.com:5443` |
| Home URL | `https://cds.example.com:5443/` |
| Admin URL | `https://cds.example.com:5443` |
| Valid redirect URIs | `https://cds.example.com:5443/callback` |
| Valid post logout redirect URIs | `https://cds.example.com:5443/` |
| Web origins | `https://cds.example.com:5443` |

Use your real host in above URLs Example:

```text
https://openwifi.routerarchitects.com:5443
```

---

### Enable PKCE and DPoP

Open the `cds-admin-ui` client.

Go to the advanced settings and configure:

| Setting | Value |
|---|---|
| Proof Key for Code Exchange Code Challenge Method | `S256` |
| OAuth 2.0 DPoP Bound Access Tokens | On |

Save the client.

---

### Add Audience Mapper

The CDS backend expects the access token audience to include cds-service.

Add an audience mapper to the `cds-admin-ui` client.

Go to `Client scopes` and select `cds-admin-ui-dedicated`

Click on `Configure a new mapper`:

| Field | Value |
|---|---|
| Select Mapper type | Audience |
| Name | `cds-service-audience` |
| Included Client Audience | `cds-service` |
| Add to access token | On |
| Add to ID token | Off |

Save the mapper.

---

### Create Admin User

Create a user, for example:

| Field | Value |
|---|---|
| Username | `admin1` |
| Email | `admin1@example.com` |
| First name | `Admin` |
| Last name | `User` |
| Email verified | On |

Go to credentials of `admin1` user
Set password:

```text
Admin@123
```

Set Temporary to:

```text
Off
```

Use a stronger password for real deployments.

---

### Assign Role To Created User (`admin1`)

After creating user `admin1`, assign the required `cds-admin` role.

In Keycloak Admin Console:
1. Go to `Users` and Select `admin1`.
2. Open `Role mapping`.
3. Click `Assign role`.
4. Select `cds-service` -> `cds-admin`.
5. Save.


---

## Verify Deployment

### Verify Container Status

```bash
cd ~/cds_workspace/ra-cds-service/cds_deploy
docker compose ps
```

Expected:

```text
cds-postgres   running / healthy
cds-keycloak   running
cds-api        running / healthy
cds-nginx      running
```

---

### Verify Nginx Admin UI Route

Open:

```text
https://cds.example.com:5443/
```

Expected:

- Admin UI loads.
- Login button is visible.
- Browser may warn if using a private/self-signed certificate.

---

### Verify JWKS From Host

```bash
curl -k https://cds.example.com:5443/keycloak/realms/cds/protocol/openid-connect/certs
```

Expected:

```json
{
  "keys": [...]
}
```

---


## Test Admin UI Flow

Open:

```text
https://cds.example.com:5443/
```

Steps:

1. Click sign in with Keycloak.
2. Login with the admin user, for example:
   ```text
   admin1 / Admin@123
   ```
3. Confirm dashboard loads after callback.
4. Confirm the UI indicates Keycloak DPoP auth mode.
5. Add a device mapping.

Use a lowercase MAC-style serial:

```text
aa:bb:cc:dd:ee:ff
```
Use a controller endpoint appropriate for your environment:

```text
openwifi.routerarchitects.com
```
---
5. Update device with another endpoint.
6. Delete device entry with Delete button.

## Test Device mTLS Lookup

Device-facing lookup route:

```text
https://cds.example.com:4443/v1/devices/{serial}
```

This route requires a valid client certificate signed by the configured CA.

Example:

```bash
curl -k https://cds.example.com:4443/v1/devices/aa:bb:cc:dd:ee:ff \
  --cacert operational.ca \
  --cert operational.pem \
  --key key.pem
```

Expected response:

```json
{
  "controller_endpoint": "openwifi3.routerarchitects.com",
  "serial": "aa:bb:cc:dd:ee:ff"
}
```
---


## Cloud Firewall / Security Group

Allow inbound:

| Port | Purpose |
|---|---|
| `5443/tcp` | Admin UI, Keycloak, Admin API |
| `4443/tcp` | Device-facing mTLS API |
| `22/tcp` | SSH from trusted source IPs only |

---

## Troubleshooting

### Admin UI does not load

Check Nginx logs:

```bash
docker compose logs --tail=100 nginx
```

Verify Admin UI build output exists:

```bash
ls -la ~/cds_workspace/mc-cds-ui/cds-admin-ui/dist/
```

Verify the Nginx volume path in `docker-compose.yml`.

---

### Keycloak login fails or redirects incorrectly

Check all of these values match the same public host and port:

- `VITE_KEYCLOAK_ISSUER`
- `KEYCLOAK_ISSUER_URL`
- `KEYCLOAK_JWKS_URL`
- `KC_HOSTNAME`
- Keycloak client Root URL
- Keycloak Valid redirect URIs
- Keycloak Web origins

Expected public base URL:

```text
https://cds.example.com:5443
```

---

### CDS returns `401 invalid access token`

Check:

- Access token issuer matches `KEYCLOAK_ISSUER_URL`.
- Access token audience includes `cds-service`.
- User has `cds-service / cds-admin` role.
- Keycloak JWKS URL is reachable from `cds-api`.
- CDS can validate the Keycloak TLS certificate.

Check CDS logs:

```bash
docker compose logs --tail=200 cds-api
```

---

### CDS returns DPoP `htu` mismatch

DPoP `htu` must match the exact external URL used by the browser.

Check:

- Nginx sends:
  - `X-Forwarded-Proto`
  - `X-Forwarded-Host`
  - `X-Forwarded-Port`
- `TRUSTED_PROXY_CIDRS` is set to the Nginx static IP CIDR (`10.42.3.10/32` by default).
- Browser URL uses the same host/port as Keycloak and Admin UI config.
- Do not change ports without updating all config files.

---

### Device mTLS request fails

Check:

- Device client certificate is signed by CA in `device-client-ca.pem`.
- `ssl_verify_client on;` is configured on port `4443`.
- Client sends `--cert` and `--key`.
- Device-facing server certificate is trusted by the client.
- Certificate SAN contains the hostname used by devices.

Check Nginx logs:

```bash
docker compose logs --tail=100 nginx
```

---

### Database row not found

Check table contents:

```bash
docker exec -it cds-postgres psql -U postgres -d cds -x -c "SELECT * FROM public.devices;"
```

Confirm:

- `serial` entry exists in lowercase.
- `owner_scope` belongs to the logged-in Keycloak subject.
- You are using the same admin user that created the row.

---

### Schema mismatch

Align:

```text
cds_deploy/db/init.sql
```

with:

```text
cds_service/internal/adapters/postgres/devices_repo.go
```

---

## Security Notes

- Do not expose `cds-api` directly to the public internet.
- Do not expose PostgreSQL publicly.
- Use strong Keycloak admin credentials.
- Use production certificates for public deployments.
- Keep private keys out of Git.
- Nginx enforces TLSv1.2/TLSv1.3, adds baseline Admin UI security headers, and applies conservative rate limits to Keycloak, admin API, and device lookup routes.
- DPoP replay protection uses an in-memory `jti` cache and is instance-local. Multi-instance CDS deployments require a shared replay cache such as Redis.
- Device-facing lookup is currently global for any successfully mTLS-verified device client. CDS does not yet bind the verified client certificate identity to the requested serial.

---

## Expected Successful Result

A successful deployment should have:

- Admin UI available at:
  ```text
  https://cds.example.com:5443/
  ```
- Keycloak Admin Console available at:
  ```text
  https://cds.example.com:5443/keycloak/admin
  ```
- Admin UI login redirects to Keycloak and back to `/callback`.
- Admin dashboard loads after login.
- Admin UI can add, update, list, and delete device mappings.
- CDS API logs show successful DPoP-authenticated admin requests.
- Device-facing mTLS lookup returns the expected controller endpoint.
- PostgreSQL contains rows in `public.devices`.

---

## License

SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial

Copyright (c) 2025 Infernet Systems Pvt Ltd
