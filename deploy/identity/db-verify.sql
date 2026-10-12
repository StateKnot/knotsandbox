-- Run as the dedicated Keycloak login using libpq sslmode=verify-full and the reviewed RDS CA.
\set ON_ERROR_STOP on
DO $$
DECLARE acceptable boolean;
BEGIN
  SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
  INTO acceptable FROM pg_roles WHERE rolname=current_user;
  IF NOT acceptable OR current_user <> 'keycloak_prod' OR current_database() <> 'keycloak_prod' THEN
    RAISE EXCEPTION 'independent Keycloak database role required';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl) THEN
    RAISE EXCEPTION 'database TLS required';
  END IF;
END $$;
