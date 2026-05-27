SELECT 'CREATE DATABASE cds'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cds')\gexec

SELECT 'CREATE DATABASE keycloak'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'keycloak')\gexec

\connect cds

CREATE TABLE IF NOT EXISTS public.devices (
  serial TEXT PRIMARY KEY,
  controller_endpoint TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  owner_scope TEXT
);

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
