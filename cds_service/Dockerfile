# SPDX-License-Identifier: AGPL-3.0 OR LicenseRef-Commercial
# Copyright (c) 2025 Infernet Systems Pvt Ltd

FROM golang:1.22 AS build
WORKDIR /src
COPY . ./
RUN go mod download && go mod tidy
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/cds ./cmd/app

# -------- Runtime stage (has curl & shell for healthcheck) --------
FROM debian:bookworm-slim
# add curl and certs for outbound HTTPS calls (token validator, etc.)
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
# run as non-root
RUN useradd -r -u 10001 -g root appuser
WORKDIR /
COPY --from=build /out/cds /cds
EXPOSE 8080
USER appuser
ENTRYPOINT ["/cds"]

