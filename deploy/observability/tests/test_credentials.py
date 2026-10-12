from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from credentials import prepare


def tls_fixture(path):
    now = datetime.now(timezone.utc)
    def ca(name):
        key = ec.generate_private_key(ec.SECP256R1()); subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=7)).add_extension(x509.BasicConstraints(ca=True,path_length=1),True).add_extension(x509.KeyUsage(True,False,False,False,False,True,True,False,False),True).sign(key,hashes.SHA256())
        return key, cert
    rootkey, root = ca('offline scraper root'); _,control=ca('offline control root'); _,server=ca('offline node server root')
    key=ec.generate_private_key(ec.SECP256R1())
    client=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'offline agent')])).issuer_name(root.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=3)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),False).sign(rootkey,hashes.SHA256())
    files={'username':b'offline_writer','password':b'OFFLINE_ONLY_NON_CLOUD_CREDENTIAL','client-cert':client.public_bytes(serialization.Encoding.PEM),'client-key':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),'scraper-ca':root.public_bytes(serialization.Encoding.PEM),'controller-ca':control.public_bytes(serialization.Encoding.PEM),'server-ca':server.public_bytes(serialization.Encoding.PEM)}
    for name, data in files.items():
        (path/name).write_bytes(data);(path/name).chmod(0o600)
    return [path/n for n in files]


class CredentialTest(unittest.TestCase):
    def test_real_chain_and_key_match_then_mismatches_and_shared_ca_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); args=tls_fixture(p)
            values=prepare(*args)
            self.assertEqual([set(v['data']) for v in values],[{'username','password'},{'tls.crt','tls.key','ca.crt'}])
            bad=list(args);bad[5]=args[4]
            with self.assertRaises(ValueError):prepare(*bad)
            bad=list(args);bad[4]=args[5]
            with self.assertRaises(ValueError):prepare(*bad)
            (p/'client-key').write_bytes(ec.generate_private_key(ec.SECP256R1()).private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            with self.assertRaises(ValueError):prepare(*args)

    def test_credential_permissions_and_basic_delimiters_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);args=tls_fixture(p)
            for v in [b'bad:user',b'bad\nuser',b'']:
                (p/'username').write_bytes(v)
                with self.assertRaises(ValueError):prepare(*args)
            (p/'username').write_bytes(b'offline_writer');(p/'password').chmod(0o644)
            with self.assertRaises(ValueError):prepare(*args)


if __name__=='__main__':unittest.main()
