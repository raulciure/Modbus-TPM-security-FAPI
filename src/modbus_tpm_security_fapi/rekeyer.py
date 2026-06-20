from time import time
from enum import IntEnum
from typing import Final
from src.modbus_tpm_security_fapi.security import ECC_key_gen, ECDHE_key_agreement, ECC_key_export, ECC_public_key_import


class RekeyStates(IntEnum):
    REKEY_NONE = 0x00
    REKEY_INIT = 0x01
    REKEY_REPLY = 0x02
    REKEY_SWITCH = 0x03
    REKEY_SWITCH_ACK = 0x04
    REKEY_FAIL = 0x05

    SHARED_SECRET_FLAGS : tuple[int, int]

    @staticmethod
    def is_valid(rekey_flag : int):
        if rekey_flag in range(RekeyStates.REKEY_NONE, RekeyStates.REKEY_FAIL + 1):
            return True
        return False


RekeyStates.SHARED_SECRET_FLAGS = (RekeyStates.REKEY_INIT, RekeyStates.REKEY_REPLY)


class Rekeyer:
    __rekey_time : int

    __recv_state : int  # Current state of the rekeyer
    __send_state : int  # Next state for the peer's rekeyer

    __peer_shared_secret = None
    __own_secret = None

    __old_sym_key = None
    __new_sym_key = None

    __rekey_switch_time : int   # Time at which the last rekey was performed

    __is_initiator = None

    __fail_flag = False
    __rekey_clear = False           # Flag indicating whether change to new key should happen (is cleared to happen)

    __debug_flag : int             # Flag indicating if debug information should be printed


    def __init__(self, rekey_time : int, *, recv_state : int = RekeyStates.REKEY_NONE, send_state : int = RekeyStates.REKEY_NONE, debug_flag : int = 0) -> None:
        self.__recv_state = recv_state
        self.__send_state = send_state
        self.__rekey_time : Final[int] = rekey_time
        self.__debug_flag = debug_flag

        self.__rekey_switch_time = int(time())

    # Method for reverting class attributes (except sym keys) to original state
    def __reset_most(self):
        self.__peer_shared_secret = self.__own_secret = None
        self.__is_initiator = None
        self.__fail_flag = False

    # Method for reverting/clearing sym keys
    def __reset_sym(self):
        self.__old_sym_key = self.__new_sym_key = None
        self.__rekey_clear = False

    # Method for reverting all class attributes to original state, after rekeying operation has ended
    def __reset_all(self):
        self.__reset_most()
        self.__reset_sym()

    def __generate_new_key(self):
        if self.__own_secret is None:
            raise ValueError("[__generate_new_key()] self.__own_secret is None")
        if self.__peer_shared_secret is None or self.__peer_shared_secret == b'':
            raise ValueError("[__generate_new_key()] self.__peer_shared_secret is None or b''")
        self.__new_sym_key = ECDHE_key_agreement(self.__own_secret, ECC_public_key_import(self.__peer_shared_secret))

    def set_fail_flag(self):
        self.__fail_flag = True

    def get_old_key(self) -> bytes | None:
        return self.__old_sym_key

    def get_new_key(self, *, called_before_send) -> bytes | None:
        if self.__fail_flag == True:        # If peer has failed rekeying => return old_sym_key
            reutrn_key = self.__old_sym_key
            self.__reset_all()
            return reutrn_key

        if self.__rekey_clear is False:     # If switching to new key is not yet cleared => return None
            return None

        if self.__is_initiator is True:
            if not called_before_send:      # Initiator must change key before sending new message (only apply new key to the new send message / decrypt received message usign current(old) key)
                return None
        else:
            if called_before_send:          # Replier must change key after receiving new message (apply new key before decrypting received message)
                return None
        
        return self.__new_sym_key
    
    def get_send_state(self, socket_reset_flag : bool) -> int:
        if socket_reset_flag == True:           # Here set send_stat for case when message is SOCKET_RESET_MESSAGE
            self.__send_state = RekeyStates.REKEY_NONE
            self.__reset_all()
        
        if self.__debug_flag >= 3:
            print("\t---Getting send flag---")
            print("\tsend_rekey_flag = ", self.__send_state)

        return self.__send_state
    
    def get_own_public_secret(self) -> bytes:    
        if self.__send_state in RekeyStates.SHARED_SECRET_FLAGS:
            if self.__own_secret is not None:
                return ECC_key_export(self.__own_secret.public_key())
            else:
                raise ValueError("[get_own_public_secret()] self.__own_secret is None when it should have been EccKey")
        else:
            return b''  # Return empty bytes object

    # Method that handles the running between rekeying operations (and also initiated rekeying)
    def handle_rekey(self, current_sym_key : bytes, recv_rekey_flag : int, peer_shared_secret : bytes):
        if not RekeyStates.is_valid(recv_rekey_flag):
            raise ValueError("\t*** [handle_rekey()] recv_rekey_flag not within specified range! ***")

        self.__old_sym_key = current_sym_key
        self.__recv_state = recv_rekey_flag
        
        if self.__recv_state in RekeyStates.SHARED_SECRET_FLAGS:
            if peer_shared_secret != b'':
                self.__peer_shared_secret = peer_shared_secret
            else:
                raise ValueError("peer_shared_secret is b'' when it should contain shared secret")
        else:
            if peer_shared_secret != b'':
                raise ValueError("peer_shared_secret contains shared secret when it should be b''")      
            
        if self.__recv_state == RekeyStates.REKEY_NONE:
            if int(time()) - self.__rekey_switch_time >= self.__rekey_time:
                self.__is_initiator = True
                self.__handle_rekey_initiator()
            else:
                self.__send_state = RekeyStates.REKEY_NONE
                self.__reset_sym()

        elif self.__recv_state == RekeyStates.REKEY_INIT:
            self.__is_initiator = False
            self.__handle_rekey_replier()

        elif self.__recv_state == RekeyStates.REKEY_FAIL:
            self.__send_state = RekeyStates.REKEY_NONE
            self.__reset_all()
        
        else:
            if self.__fail_flag == True:
                self.__send_state = RekeyStates.REKEY_NONE
                self.__reset_all()
                return
        
            if self.__is_initiator == True:
                self.__handle_rekey_initiator()
            elif self.__is_initiator == False:
                self.__handle_rekey_replier()
            else:
                raise ValueError("__is_initiator is not bool type (is None)")
        
        if self.__debug_flag >= 3:
            print("\t---Handling rekey data---")
            print("\trecv_rekey_flag = ", self.__recv_state)
            print("\tsend_rekey_flag = ", self.__send_state)

    # Method that handles the running during rekeying for INITIATOR
    def __handle_rekey_initiator(self):
        if self.__recv_state == RekeyStates.REKEY_NONE:
            self.__send_state = RekeyStates.REKEY_INIT
            self.__own_secret = ECC_key_gen()

        elif self.__recv_state == RekeyStates.REKEY_REPLY:
            try:
                self.__send_state = RekeyStates.REKEY_SWITCH
                self.__generate_new_key()       # This can raise ValueError
                self.__rekey_clear = True       # New key can now be used
            except ValueError as e:
                self.__send_state = RekeyStates.REKEY_FAIL
                self.__fail_flag = True
                print("\t*** ECDHE_key_agreement ValueError! ***")
                print("\t", e)

        elif self.__recv_state == RekeyStates.REKEY_SWITCH_ACK:
            self.__rekey_switch_time = int(time())          # Set rekey time to current time
            self.__send_state = RekeyStates.REKEY_NONE
            if self.__debug_flag >= 3:
                print("\t* New ECDH key exchange performed! *")
            self.__reset_all()  # Reset attributes to default (to be ready for next rekeying)


    # Method that handles the running during rekeying for REPLIER
    def __handle_rekey_replier(self):
        if self.__recv_state == RekeyStates.REKEY_INIT:
            try:
                self.__send_state = RekeyStates.REKEY_REPLY
                self.__own_secret = ECC_key_gen()
                self.__generate_new_key()      # This can raise ValueError
            except ValueError as e:
                self.__send_state = RekeyStates.REKEY_FAIL
                self.__reset_all()
                print("\t*** ECDHE_key_agreement ValueError! ***")
                print("\t", e)

        elif self.__recv_state == RekeyStates.REKEY_SWITCH:
            if self.__new_sym_key is not None:
                self.__send_state = RekeyStates.REKEY_SWITCH_ACK
                self.__rekey_clear = True       # New key can now be used

                self.__rekey_switch_time = int(time())  # Set rekey time to current time
                if self.__debug_flag >= 3:
                    print("\t* New ECDH key exchange performed! *")
                self.__reset_most()
            else:
                self.__send_state = RekeyStates.REKEY_FAIL
                self.__reset_all()
                raise ValueError("self.__new_sym_key is None when it should have been bytes")


# Class that overrides Rekeyer methods to make them have no effect
class RekeyerDisabler(Rekeyer):
    def __init__(self) -> None:
        return
    
    def get_old_key(self):
        return None
    
    def get_new_key(self, *, called_before_send):
        return None

    def get_send_state(self, socket_reset_flag : bool = False) -> int:
        return RekeyStates.REKEY_NONE
    
    def get_own_public_secret(self) -> bytes:
        return b''

    def handle_rekey(self, current_sym_key : bytes, recv_rekey_flag : int, peer_shared_secret : bytes):
        return