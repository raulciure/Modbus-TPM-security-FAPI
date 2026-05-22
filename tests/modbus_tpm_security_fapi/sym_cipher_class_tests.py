import random
from src.modbus_tpm_security_fapi.sym_cipher import *


# cipher_obj = SymCipher_ChaCha20(None, random.randbytes(32))
cipher_obj = SymCipher_GCM(None, random.randbytes(32))
# cipher_obj = SymCipher_EAX(None, random.randbytes(32))

message = "Hello there!"
print("message size = ", len(message), "\n")

enc_message = cipher_obj.encrypt_and_digest(message.encode())
print("enc_message size = ", len(enc_message))
print("enc_message = ", enc_message, "\n")

dec_message = cipher_obj.decrypt_and_verify(enc_message)
print("dec_message = ", dec_message)