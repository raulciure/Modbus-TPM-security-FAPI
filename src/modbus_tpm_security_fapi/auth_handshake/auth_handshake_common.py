import socket
import struct
import os

from src.modbus_tpm_security_fapi.netcomm import NetComm
from src.modbus_tpm_security_fapi.tpm_security import TpmSigner, TpmSealer, get_random
from src.modbus_tpm_security_fapi.security import verify_RSA_signature


TPM_SIGN_KEY_NAME = "dev_auth_key"
TPM_PEER_PUB_KEY_SEAL_NAME = "peer_auth_pub_key_seal"
PEER_PUB_KEY_FILE_NAME = "peer_auth_pub_key"

HEADER_FORMAT = "!HHH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def pack(rand : bytes, signature : bytes, pub_key : str | None = None) -> bytes:
    if pub_key is None:
        pub_key = ""
    pub_key_bytes = pub_key.encode()

    header = struct.pack(HEADER_FORMAT, len(rand), len(signature), len(pub_key_bytes))

    payload_fmt = f"!{len(rand)}s{len(signature)}s{len(pub_key_bytes)}s"
    payload = struct.pack(payload_fmt, rand, signature, pub_key_bytes)

    return (header + payload)


def unpack(data : bytes) -> tuple[bytes, bytes, str]:
    rand_size, signature_size, pub_key_size = struct.unpack_from(HEADER_FORMAT, data)

    payload_fmt = f"!{rand_size}s{signature_size}s{pub_key_size}s"
    rand, signature, pub_key_bytes = struct.unpack_from(payload_fmt, data, HEADER_SIZE)

    return (rand, signature, pub_key_bytes.decode())


def auth_key_exchange(conn_socket : socket.socket, *, is_client : bool):
    communicator = NetComm(conn_socket)

    tpm_signer = TpmSigner(TPM_SIGN_KEY_NAME)
    tpm_signer.create_key(system_key=True)

    own_rand = get_random(32)

    signature, own_pub_key, _ = tpm_signer.sign_data(own_rand)

    peer_rand : bytes
    peer_signature : bytes
    peer_public_key : str
    
    if is_client is True:
        # Send own tpm public key to peer
        communicator.send(pack(own_rand, signature, own_pub_key))    # Here send own public key
        print("Sent own public key & own signed rand!")

        peer_rand, peer_signature, peer_public_key = unpack(communicator.receive())
        print("Recieved peer public key & peer signed rand!")

        if verify_RSA_signature(peer_public_key, peer_rand, peer_signature) is False:
            print("Received signature (for peer rand) is not valid!")
            return
        print("Received valid peer signature for peer rand!")

        # Then, send peer_rand signed with own_key
        peer_rand_signed_own, _, _ = tpm_signer.sign_data(peer_rand)
        communicator.send(pack(peer_rand, peer_rand_signed_own))

        # Receive own_rand, signed with peer_key, from peer
        own_rand_from_peer, own_rand_from_peer_signature, _ = unpack(communicator.receive())
        print("Recieved own rand signed with peer's key!")

        if verify_RSA_signature(peer_public_key, own_rand_from_peer, own_rand_from_peer_signature) is False:
            print("Received signature (for own rand) is not valid!")
            return
        print("Received valid peer signature for own rand!")

    else:
        # Recieve the public key from peer
        peer_rand, peer_signature, peer_public_key = unpack(communicator.receive())
        print("Recieved peer public key & peer signed rand!")

        if verify_RSA_signature(peer_public_key, peer_rand, peer_signature) is False:
            print("Received signature (for peer rand) is not valid!")
            return
        print("Received valid peer signature for peer rand!")

        # Then send own tpm public key to peer
        communicator.send(pack(own_rand, signature, own_pub_key))    # Here send own public key
        print("Sent own public key & own signed rand!")

        # Receive own_rand, signed with peer_key, from peer
        own_rand_from_peer, own_rand_from_peer_signature, _ = unpack(communicator.receive())
        print("Recieved own rand signed with peer's key!")

        if verify_RSA_signature(peer_public_key, own_rand_from_peer, own_rand_from_peer_signature) is False:
            print("Received signature (for own rand) is not valid!")
            return
        print("Received valid peer signature for own rand!")

        # Then, send peer_rand signed with own_key
        peer_rand_signed_own, _, _ = tpm_signer.sign_data(peer_rand)
        communicator.send(pack(peer_rand, peer_rand_signed_own))
    
    # Seal peer_public_key hash in the TPM, to prevent tampering     
    peer_public_key_bytes = peer_public_key.strip().encode()
    if TpmSealer(TPM_PEER_PUB_KEY_SEAL_NAME).link_with_seal(peer_public_key_bytes, system_seal=True) is False:
        print("Peer device was NOT associated!")
        return
    print("Peer public key hash sealed inside TPM!")
    print("<<< PEER DEVICE IS NOW ASSOCIATED WITH THIS DEVICE! >>>")

    # Write peer_public_key to disk
    file_name = PEER_PUB_KEY_FILE_NAME
    current_script_path = os.path.dirname(os.path.abspath(__file__))
    file = open(os.path.join(current_script_path, file_name), 'wb')
    file.write(peer_public_key_bytes)
    file.close()
