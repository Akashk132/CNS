from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class PKIManager:
    def __init__(self):
        self.ca_records = {}
        self.cert_records = {}

    def build_root_ca(self, name: str, organization: str = "LabCA", country: str = "IN"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        dn = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper()),
        ])
        t_start = datetime.now(timezone.utc)
        t_end = t_start + timedelta(days=3650)
        cert = (
            x509.CertificateBuilder()
            .subject_name(dn)
            .issuer_name(dn)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(t_start)
            .not_valid_after(t_end)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False, data_encipherment=False,
                    key_agreement=False, encipher_only=False, decipher_only=False
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        key_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode("utf-8")
        self.ca_records[name] = {"cert_pem": cert_pem, "key_pem": key_pem, "subject": str(dn)}
        return cert_pem

    def issue_leaf_cert(self, ca_name: str, domain: str, organization: str = "MemberOrg", country: str = "IN"):
        if ca_name not in self.ca_records:
            raise KeyError(f"Root authority {ca_name} not registered")
        parent_ca = self.ca_records[ca_name]
        parent_cert = x509.load_pem_x509_certificate(parent_ca["cert_pem"].encode("utf-8"))
        parent_key = serialization.load_pem_private_key(parent_ca["key_pem"].encode("utf-8"), password=None)

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject_dn = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country[:2].upper()),
        ])
        t_start = datetime.now(timezone.utc)
        t_end = t_start + timedelta(days=365)
        leaf_cert = (
            x509.CertificateBuilder()
            .subject_name(subject_dn)
            .issuer_name(parent_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(t_start)
            .not_valid_after(t_end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(parent_key, hashes.SHA256())
        )
        cert_pem = leaf_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        key_pem = leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode("utf-8")
        self.cert_records[domain] = {
            "cert_pem": cert_pem,
            "key_pem": key_pem,
            "issued_by": ca_name,
            "subject": str(subject_dn),
            "valid_from": t_start.isoformat(),
            "valid_until": t_end.isoformat(),
        }
        return cert_pem

    def validate_leaf(self, domain: str):
        if domain not in self.cert_records:
            return False, "Certificate unknown"
        record = self.cert_records[domain]
        issuer_name = record["issued_by"]
        if issuer_name not in self.ca_records:
            return False, "Issuer missing"
        root_ca = self.ca_records[issuer_name]

        ca_cert = x509.load_pem_x509_certificate(root_ca["cert_pem"].encode("utf-8"))
        leaf_cert = x509.load_pem_x509_certificate(record["cert_pem"].encode("utf-8"))
        try:
            ca_cert.public_key().verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf_cert.signature_hash_algorithm
            )
            return True, "VALID"
        except Exception as err:
            return False, f"Signature rejected: {err}"

pki_engine = PKIManager()
