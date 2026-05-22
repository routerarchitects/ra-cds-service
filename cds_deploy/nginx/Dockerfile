FROM nginx:1.27-alpine
COPY cds.conf /etc/nginx/conf.d/default.conf
COPY certs/device-server-cert.pem /etc/ssl/certs/device-server-cert.pem
COPY certs/device-server-key.pem /etc/ssl/private/device-server-key.pem

COPY certs/admin-server-cert.pem /etc/ssl/certs/admin-server-cert.pem
COPY certs/admin-server-key.pem /etc/ssl/private/admin-server-key.pem

COPY certs/device-client-ca.pem /etc/ssl/certs/device-client-ca.pem
EXPOSE 4443 5443
