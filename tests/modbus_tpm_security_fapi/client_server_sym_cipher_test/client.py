import socket
from argparse import Namespace
from src.modbus_tpm_security_fapi.netcomm import NetComm
from src.modbus_tpm_security_fapi.sym_cipher import SymCipher_GCM
from Crypto.Random import get_random_bytes
from time import sleep


args = Namespace(
    set_rekey_interval = 5,
    disable_replay_resistance = True,

    disable_rekeying = False,
    debug_option = True,
)

sym_key = bytes.fromhex("53 8e d5 34 b7 71 67 9e 04 3f 1f 54 c5 88 91 8c 3d 43 48 01 24 af 3b bd 73 00 bc 4e 14 39 1f c9")


def client():
    dest_ip = '127.0.0.1'
    dest_port = 4020

    dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dest_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)     # Set TCP_NODELAY
    dest_socket.connect((dest_ip, dest_port))

    print(f"[*] Established connection to server: {(dest_ip, dest_port)}")

    communicator = NetComm(dest_socket)
    cipher = SymCipher_GCM(args, sym_key)

    try:
        while True:
            send_msg = get_random_bytes(10)
            print("send_msg = ", send_msg)
            send_msg_enc = cipher.encrypt_and_digest(send_msg)
            print("send_msg_enc = ", send_msg_enc)

            communicator.send(send_msg_enc)

            print()

            recv_msg_enc = communicator.receive()
            print("recv_msg_enc = ", recv_msg_enc)
            recv_msg = cipher.decrypt_and_verify(recv_msg_enc)
            print("recv_msg = ", recv_msg)

            print("\n--------------------------------------------------------------\n")

            sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        dest_socket.close()


if __name__ == "__main__":
    client()
    