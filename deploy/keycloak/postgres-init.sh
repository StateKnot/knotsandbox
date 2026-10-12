#!/usr/bin/env bash
# Local Compose bootstrap only. Never mount this into a production database.
set -euo pipefail
: "${SANDBOX_DB_PASSWORD:?Missing development application password}"
: "${SANDBOX_MIGRATION_DB_PASSWORD:?Missing development migration password}"
: "${SANDBOX_WORKER_DB_PASSWORD:?Missing development worker password}"
: "${SANDBOX_ADMISSION_DB_PASSWORD:?Missing development admission password}"
: "${SANDBOX_GATEWAY_DB_PASSWORD:?Missing development gateway password}"
: "${SANDBOX_TERMINATION_DB_PASSWORD:?Missing development termination password}"
: "${SANDBOX_FENCING_DB_PASSWORD:?Missing development fencing password}"
: "${SANDBOX_BACKUP_DB_PASSWORD:?Missing development backup password}"
: "${SANDBOX_VOLUME_DELETER_DB_PASSWORD:?Missing development volume deleter password}"
: "${SANDBOX_KEYCLOAK_DB_PASSWORD:?Missing development identity password}"

psql --username "$POSTGRES_USER" --dbname postgres --set ON_ERROR_STOP=1 \
  --set app_password="$SANDBOX_DB_PASSWORD" \
  --set owner_password="$SANDBOX_MIGRATION_DB_PASSWORD" \
  --set worker_password="$SANDBOX_WORKER_DB_PASSWORD" \
  --set admission_password="$SANDBOX_ADMISSION_DB_PASSWORD" \
  --set gateway_password="$SANDBOX_GATEWAY_DB_PASSWORD" \
  --set termination_password="$SANDBOX_TERMINATION_DB_PASSWORD" \
  --set fencing_password="$SANDBOX_FENCING_DB_PASSWORD" \
  --set backup_password="$SANDBOX_BACKUP_DB_PASSWORD" \
  --set volume_deleter_password="$SANDBOX_VOLUME_DELETER_DB_PASSWORD" \
  --set identity_password="$SANDBOX_KEYCLOAK_DB_PASSWORD" <<'SQL'
CREATE ROLE sandbox_owner LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'owner_password';
CREATE ROLE sandbox_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'app_password';
CREATE ROLE sandbox_worker LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'worker_password';
CREATE ROLE sandbox_admission LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'admission_password';
CREATE ROLE sandbox_gateway LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'gateway_password';
CREATE ROLE sandbox_termination LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'termination_password';
CREATE ROLE sandbox_fencing LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'fencing_password';
CREATE ROLE sandbox_backup LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'backup_password';
CREATE ROLE sandbox_volume_deleter LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'volume_deleter_password';
CREATE DATABASE sandbox_dev OWNER sandbox_owner;
CREATE DATABASE sandbox_test OWNER sandbox_owner;
REVOKE ALL ON DATABASE sandbox_dev FROM PUBLIC;
REVOKE ALL ON DATABASE sandbox_test FROM PUBLIC;
GRANT CONNECT ON DATABASE sandbox_dev TO sandbox_app,sandbox_worker,sandbox_admission,sandbox_gateway,sandbox_termination,sandbox_fencing,sandbox_volume_deleter,sandbox_backup;
GRANT CONNECT ON DATABASE sandbox_test TO sandbox_app,sandbox_worker,sandbox_admission,sandbox_gateway,sandbox_termination,sandbox_fencing,sandbox_volume_deleter,sandbox_backup;
CREATE ROLE keycloak_dev LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'identity_password';
CREATE DATABASE keycloak_dev OWNER keycloak_dev;
REVOKE ALL ON DATABASE keycloak_dev FROM PUBLIC;
SQL
