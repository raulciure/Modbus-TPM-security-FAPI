from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Protocol import DH
from Crypto.Protocol.KDF import HKDF


def verify_RSA_signature(RSA_key : bytes | str, data : bytes, signature : bytes) -> bool:
    verifier = pss.new(RSA.import_key(RSA_key))     # Setup signature verifier
    hash = SHA256.new(data)                         # Compute hash for given data
    try:
        # Check if signature is valid
        verifier.verify(hash, signature)   # type: ignore
        return True
    except ValueError:
        return False


# Generate an ECC key
def ECC_key_gen() -> ECC.EccKey:
    ECC_CURVE = "Curve25519"    # X25519 key exchange protocol
    key = ECC.generate(curve=ECC_CURVE)    # type: ignore
    return key


# Export ECC key to bytes
def ECC_key_export(key : ECC.EccKey) -> bytes:
    exported_key = key.export_key(format='raw')
    return exported_key


def ECC_public_key_import(encoded_key : bytes) -> ECC.EccKey:
    key = DH.import_x25519_public_key(encoded_key)
    return key


# Create a common key based on both parties keys
def ECDHE_key_agreement(own_key : ECC.EccKey, peer_key : ECC.EccKey) -> bytes:
    def kdf(input):
        SALT = bytes.fromhex("aa70fb5153d697261376069b636b377f1ee0ec03fdaf452f674caa3500ce47e7")
        return HKDF(input, key_len=32, salt=SALT, hashmod=SHA256)

    session_key = DH.key_agreement(eph_priv=own_key, eph_pub=peer_key, kdf=kdf)

    if isinstance(session_key, tuple):
        raise AssertionError("[ECDHE_key_agreement] session_key is a tuple (i.e. KDF created multiple keys)")
    return session_key