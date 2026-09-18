import random
from src.modbus_tpm_security_fapi.sym_cipher import *
from types import SimpleNamespace


args = SimpleNamespace(set_replay_resistance = "seq-num",
                       disable_rekeying = True,
                       disable_replay_resistance = None,
                       v = None,
                       vv = None,
                       vvv = True,
                       is_client = True)

# cipher_obj = SymCipher_ChaCha20(args, random.randbytes(32))
cipher_obj = SymCipher_GCM(args, random.randbytes(32))
# cipher_obj = SymCipher_EAX(args, random.randbytes(32))
# cipher_obj = SymCipher_CCM(args, random.randbytes(32))

message = "Hello there!"
print("message = ", message)
print("message size = ", len(message), "\n")

enc_message = cipher_obj.encrypt_and_digest(message.encode())
print("enc_message size = ", len(enc_message))
print("enc_message = ", enc_message.hex(' '), "\n")

dec_message = cipher_obj.decrypt_and_verify(enc_message)
print("dec_message = ", dec_message)