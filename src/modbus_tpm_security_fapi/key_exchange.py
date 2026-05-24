import os
import socket
import struct
from src.modbus_tpm_security_fapi.security import *
from src.modbus_tpm_security_fapi.tpm_security import TpmSigner, TpmSealer
from src.modbus_tpm_security_fapi.netcomm import NetComm
from src.modbus_tpm_security_fapi.auth_handshake.auth_handshake_common import TPM_SIGN_KEY_NAME, TPM_PEER_PUB_KEY_SEAL_NAME, PEER_PUB_KEY_FILE_NAME


HEADER_FORMAT = "!HH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

PEER_AUTH_PUB_KEY_FILE_PATH = os.path.join("/home/raul/Desktop/Modbus-TPM-security-FAPI/src/modbus_tpm_security_fapi/auth_handshake", PEER_PUB_KEY_FILE_NAME)

def pack(data : bytes, signature : bytes) -> bytes:
    header = struct.pack(HEADER_FORMAT, len(data), len(signature))

    payload_fmt = f"!{len(data)}s{len(signature)}s"
    payload = struct.pack(payload_fmt, data, signature)

    return (header + payload)


def unpack(data : bytes) -> tuple[bytes, bytes]:
    data_size, signature_size = struct.unpack_from(HEADER_FORMAT, data)

    payload_fmt = f"!{data_size}s{signature_size}s"
    data, signature = struct.unpack_from(payload_fmt, data, HEADER_SIZE)

    return (data, signature)


def read_file(path : str, read_mode="rb"):
    file = open(path, read_mode)
    return file.read().strip()
    

# Exchanges public ECC keys (signed) between devices
# returns established shared secret
def DH_key_exchange(gateway_socket : socket.socket):
    """
    Exchanges public ECC keys (signed) between devices.

    Parameters
    ----------
    gateway_socket : socket.socket
        The socket for communicating with the peer gateway.

    Returns
    ------
    shared_key : bytes
        The shared key/secret established between the two devices.
    None
        If there was an authentication error.
    """
    
    source_address = gateway_socket.getsockname()[0]    # get IP addresses of devices
    dest_address = gateway_socket.getpeername()[0]

    file_peer_auth_pub_key = read_file(PEER_AUTH_PUB_KEY_FILE_PATH)

    # Check if local peer_auth_pub_key is authentic (with TPM), to make sure the other device is the known one
    if TpmSealer(TPM_PEER_PUB_KEY_SEAL_NAME).verify_with_seal(file_peer_auth_pub_key) is False:
        print("*** peer_auth_pub_key is NOT the one linked to the TPM! ***")
        return None
    print("peer_auth_pub_key verified locally with the TPM!")

    ECC_key_own =  ECC_key_gen()                        # Generate ephemeral ECC key
    print("ECC key generated!")
    ECC_key_own_public_bytes = ECC_key_export(ECC_key_own.public_key())

    ECC_key_own_public_bytes_signature, _, _ = TpmSigner(TPM_SIGN_KEY_NAME).sign_data(ECC_key_own_public_bytes)     # Sign ECC_key_own_public_bytes using TPM based dev_auth_key

    communicator = NetComm(gateway_socket)

    if(source_address <= dest_address):  # source sends the key firsts
        communicator.send(pack(ECC_key_own_public_bytes, ECC_key_own_public_bytes_signature))       # source sends its public key to dest
        print("Sent \"ECC_key_own_public_bytes_signed\"")

        ECC_key_peer_public_key, ECC_key_peer_public_signature = unpack(communicator.receive())     # then recieves the public key from dest
        print("Recieved \"ECC_key_peer_public_bytes_signed\"")
    else:                               # dest sends the key first
        ECC_key_peer_public_key, ECC_key_peer_public_signature = unpack(communicator.receive())     # source recieves the public key from dest
        print("Recieved \"ECC_key_peer_public_bytes_signed\"")

        communicator.send(pack(ECC_key_own_public_bytes, ECC_key_own_public_bytes_signature))       # then sends its public key to dest
        print("Sent \"ECC_key_own_public_bytes_signed\"")

    if verify_RSA_signature(file_peer_auth_pub_key, ECC_key_peer_public_key, ECC_key_peer_public_signature) is False:
        print("**** !!! RSA signature is not authentic !!! ****")
        return None
    print("RSA signature is authentic")

    shared_key = ECDHE_key_agreement(ECC_key_own, ECC_public_key_import(ECC_key_peer_public_key))
    print("Established shared key")

    return shared_key
