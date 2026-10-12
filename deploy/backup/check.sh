#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
py="${BACKUP_PYTHON:-python3}"
"$py" -m unittest discover -s deploy/backup/tests -p 'test_*.py'
"$py" -m py_compile deploy/backup/backup.py deploy/backup/inventory.py deploy/backup/reader_credentials.py deploy/backup/reader_config.py deploy/backup/deploy.py deploy/backup/prepare.py deploy/backup/verify_image.py deploy/backup/verify_runtime.py deploy/backup/controller.py deploy/backup/profile.py
"$py" deploy/backup/schema_check.py
if [[ -n "${BACKUP_RESTIC_BIN:-}" && -n "${BACKUP_RCLONE_BIN:-}" ]]; then
  "$py" deploy/backup/tests/local_restic.py --restic "$BACKUP_RESTIC_BIN" --rclone "$BACKUP_RCLONE_BIN" --openssl "${BACKUP_OPENSSL_BIN:-openssl}"
  "$py" deploy/backup/tests/rclone_sts.py --rclone "$BACKUP_RCLONE_BIN" --openssl "${BACKUP_OPENSSL_BIN:-openssl}"
fi
