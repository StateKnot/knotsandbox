-- Run once using the RDS privileged database administrator over verified TLS.
-- Fixed independent name; no product database/role grants. Never use this to reset an existing account.
\set ON_ERROR_STOP on
CREATE ROLE keycloak_prod LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- psql prompts privately and sends an encrypted password; never use a literal password in SQL/argv.
\password keycloak_prod
CREATE DATABASE keycloak_prod OWNER keycloak_prod ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE keycloak_prod FROM PUBLIC;
GRANT CONNECT ON DATABASE keycloak_prod TO keycloak_prod;
\connect keycloak_prod
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO keycloak_prod;
