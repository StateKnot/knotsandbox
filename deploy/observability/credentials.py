#!/usr/bin/env python3
"""Prepare private Secret manifests from existing dedicated credentials; no kubectl/cloud writes."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from observability import load, require, metadata, write_private, SECRET_WRITER, SECRET_SCRAPER


def prepare(username, password, client_cert, client_key, scraper_ca, controller_ca, server_ca):
    user, secret = load(username, True), load(password, True)
    require(1 <= len(user) <= 1024 and 1 <= len(secret) <= 16384, 'CREDENTIAL_SIZE')
    require(all(33 <= b <= 126 for b in user + secret) and b':' not in user, 'CREDENTIAL_FORMAT')
    cert_bytes, key_bytes = load(client_cert), load(client_key, True)
    certs = x509.load_pem_x509_certificates(cert_bytes)
    readers = x509.load_pem_x509_certificates(load(scraper_ca))
    controllers = x509.load_pem_x509_certificates(load(controller_ca))
    servers = x509.load_pem_x509_certificates(load(server_ca))
    require(certs and readers and controllers and servers and len(certs) <= 8, 'TLS_CERTIFICATE')
    def key_der(cert):
        return cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    require(not ({key_der(c) for c in readers} & {key_der(c) for c in controllers + servers}), 'SCRAPER_CA_MUST_BE_SEPARATE')
    for cert in readers + controllers + servers:
        require(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'CA_CONSTRAINT')
    leaf = certs[0]
    now = datetime.now(timezone.utc)
    require(leaf.not_valid_before_utc <= now and leaf.not_valid_after_utc >= now + timedelta(days=1), 'CLIENT_CERTIFICATE_EXPIRY')
    require(not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'CLIENT_IS_CA')
    require(ExtendedKeyUsageOID.CLIENT_AUTH in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value, 'CLIENT_EKU')
    key = serialization.load_pem_private_key(key_bytes, None)
    require(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == key_der(leaf), 'CLIENT_KEY_MISMATCH')
    result = subprocess.run(['openssl', 'verify', '-no-CApath', '-no-CAstore', '-purpose', 'sslclient', '-CAfile', str(scraper_ca), '-untrusted', str(client_cert), str(client_cert)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False)
    require(result.returncode == 0, 'CLIENT_CHAIN')
    def secret_obj(name, items):
        return {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': metadata(name), 'type': 'Opaque', 'data': {k: base64.b64encode(v).decode('ascii') for k, v in items.items()}}
    return [secret_obj(SECRET_WRITER, {'username': user, 'password': secret}), secret_obj(SECRET_SCRAPER, {'tls.crt': cert_bytes, 'tls.key': key_bytes, 'ca.crt': load(server_ca)})]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for field in ('username', 'password', 'client-cert', 'client-key', 'scraper-ca', 'controller-ca', 'server-ca', 'output'):
        p.add_argument('--' + field, type=Path, required=True)
    a = p.parse_args()
    objects = prepare(a.username, a.password, a.client_cert, a.client_key, a.scraper_ca, a.controller_ca, a.server_ca)
    write_private(a.output, yaml.safe_dump_all(objects, sort_keys=False).encode())
    print('Private credential manifests prepared; no credentials printed or cluster changes performed.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, x509.ExtensionNotFound, subprocess.SubprocessError):
        print('OBSERVABILITY_CREDENTIALS_REJECTED', file=sys.stderr)
        sys.exit(1)
