import socket
from src.modbus_tpm_security_fapi.auth_handshake.auth_handshake_common import auth_key_exchange
from src.modbus_tpm_security_fapi.parse_args import parse_args_auth_handshake


def auth_handshake_client():
    # dest_ip = '192.168.81.81'
    dest_port = 4020

    args = parse_args_auth_handshake(__file__)

    if args.dest:
        dest_ip = args.dest
    elif args.dest_ip:
        dest_ip = args.dest_ip
    else:
        raise ValueError("Destination IP not specified!")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((dest_ip, dest_port))
    print(f"[*] Established connection to server: {(dest_ip, dest_port)}")

    auth_key_exchange(server_socket, is_client=True)   # Call key exchange routine

    server_socket.close()


if __name__ == "__main__":
    auth_handshake_client()