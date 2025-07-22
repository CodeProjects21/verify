from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import json

# 1. Einmalig Schlüssel generieren
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Public Key speichern (für das Spiel)
with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Private Key (für euch)
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# 2. Lizenz erstellen
license_data = {
    "user": "Max Mustermann",
    "product": "MiniGamePro",
    "valid_until": "2026-01-01"
}
license_bytes = json.dumps(license_data).encode()

# Signatur erstellen
signature = private_key.sign(
    license_bytes,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)

# Lizenzdatei (enthält Daten + Signatur)
with open("license.json", "wb") as f:
    f.write(json.dumps({
        "data": license_data,
        "signature": signature.hex()
    }).encode())
