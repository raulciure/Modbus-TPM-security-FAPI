from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Protocol import DH


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
    ECC_CURVE = "Curve25519"    # X25519 curve
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
        return SHA256.new(input)

    session_key = DH.key_agreement(eph_priv=own_key, eph_pub=peer_key, kdf=kdf)

    return session_key.digest()