import os
from src.modbus_tpm_security_fapi.tpm_security import get_obj_tpm_path, delete_obj
from src.modbus_tpm_security_fapi.auth_handshake.auth_handshake_common import TPM_SIGN_KEY_NAME, TPM_PEER_PUB_KEY_SEAL_NAME, PEER_PUB_KEY_FILE_NAME


def auth_delete_keys():
    try:
        # Delete own sign (auth) key
        delete_obj(get_obj_tpm_path(TPM_SIGN_KEY_NAME))
        print(f"Own priv key ({TPM_SIGN_KEY_NAME}) deleted!")
    except:
        print(f"*** {TPM_SIGN_KEY_NAME} could NOT be deleted! ***")

    try:
        # Delete peer pub sign (auth) seal
        delete_obj(get_obj_tpm_path(TPM_PEER_PUB_KEY_SEAL_NAME))
        print(f"Peer pub key seal ({TPM_PEER_PUB_KEY_SEAL_NAME}) deleted!")
    except:
        print(f"*** Peer pub key seal ({TPM_PEER_PUB_KEY_SEAL_NAME}) could NOT be deleted! ***")


    # Delete peer pub key file
    current_script_path = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_script_path, PEER_PUB_KEY_FILE_NAME)
    try:
        os.remove(file_path)
        print("Peer pub key file deleted!")
    except FileNotFoundError:
        print("*** Peer pub key file NOT found! ***")


if __name__ == "__main__":
    auth_delete_keys()