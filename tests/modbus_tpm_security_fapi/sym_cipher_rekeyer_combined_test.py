from argparse import Namespace
from src.modbus_tpm_security_fapi.sym_cipher import SymCipher_GCM
from Crypto.Random import get_random_bytes
from time import sleep


args = Namespace(
    set_rekey_interval = 5,
    disable_replay_resistance = True,

    disable_rekeying = False,
    debug_option = False,
)

sym_key = get_random_bytes(32)


cipher = SymCipher_GCM(args, sym_key)
counter = 1

while True:
    print(f"-------------- RUN {counter} --------------")

    msg = b"Test message!"
    print("msg = ", msg)

    enc_msg = cipher.encrypt_and_digest(msg)
    print("enc_msg = ", enc_msg)

    if enc_msg[1] != 0x00:
        aux_array = bytearray(enc_msg)
        if aux_array[1] == 0x01:
            aux_array[1] = 0x02
        elif aux_array[1] == 0x02:
            aux_array[1] = 0x03
        elif aux_array[1] == 0x03:
            aux_array[1] = 0x04
        elif aux_array[1] == 0x05:
            aux_array[1] = 0x00
        enc_msg = bytes(aux_array)

    dec_msg = cipher.decrypt_and_verify(enc_msg)
    print("dec_msg = ", dec_msg)

    print("\n")

    counter += 1

    sleep(1)

