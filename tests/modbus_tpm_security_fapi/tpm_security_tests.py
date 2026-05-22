from src.modbus_tpm_security_fapi.tpm_security import TpmSealer, TpmSigner
from hashlib import sha256


msg = "Hello there"
msg_enc = msg.encode()

print("----------- TpmSealer test -----------")
sealer = TpmSealer("msg")
sealer.seal(msg_enc)
print("Message successfully sealed!")

unsealed_msg = sealer.unseal()
print("unsealed_msg = ", unsealed_msg.decode())
sealer.delete_seal()
print("Seal deleted successfully!")
print("\n")

print("----------- TpmSigner test -----------")
signer = TpmSigner("msg_key")
signer.create_key()
signature, pub_key, cert = signer.sign_hash(sha256(msg_enc).digest())
print("Message successfully signed!")
print("signature = ", signature)
print("pub_key = ", pub_key.strip())
print("cert = ", cert, "\n")

sig_status = signer.verify_hash(sha256(msg_enc).digest(), signature)
if sig_status is True:
    print("Signature successfully verified!")
else:
    print("Signature is NOT good!")

# from tpm2_pytss import FAPI
# with FAPI() as fapi:
#     exported_key = fapi.export_key("/HS/SRK/msg_key")
#     print("exported_key:\n", exported_key, "\n")

signer.delete_key()
print("Sign key deleted successfully!")