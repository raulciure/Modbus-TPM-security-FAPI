from Crypto.Cipher.ChaCha20_Poly1305 import ChaCha20Poly1305Cipher
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from time import time
from enum import IntEnum
from src.modbus_tpm_security_fapi.packet_format import Formatter
from src.modbus_tpm_security_fapi.rekeyer import Rekeyer, RekeyerDisabler
from src.modbus_tpm_security_fapi.perf_measure.latency_measure import LatencyMeter


class CipherTypes(IntEnum):
    AES_CCM = 1
    AES_EAX = 2
    AES_GCM = 3
    AES_SIV = 4
    AES_OCB = 5
    CHACHA20 = 6

    __SIV_MODE_NONCE_SIZE = 16

    @staticmethod
    def get_cipher_index(cipher_str : str) -> int:
        if cipher_str == "AES_CCM":
            return CipherTypes.AES_CCM
        if cipher_str == "AES_EAX":
            return CipherTypes.AES_EAX
        if cipher_str == "AES_GCM":
            return CipherTypes.AES_GCM
        if cipher_str == "AES_SIV":
            return CipherTypes.AES_SIV
        if cipher_str == "AES_OCB":
            return CipherTypes.AES_OCB
        if cipher_str == "CHACHA":
            return CipherTypes.CHACHA20
        return 0
    
    @staticmethod
    def get_cipher_list_str() -> list[str]:
        attributes = [
            name for name, value in CipherTypes.__dict__.items() if not (name.startswith("__") or name.startswith("_")) and not callable(value)
        ]

        return attributes
    
    @staticmethod
    def get_cipher_formatted_list() -> str:
        attributes = CipherTypes.get_cipher_list_str()
        return str(attributes)

    @staticmethod
    def get_symcipher_from_args(args, sym_key : bytes):
        index = args.set_cipher

        if index == CipherTypes.AES_CCM:
            return SymCipher_CCM(args, sym_key)
        if index == CipherTypes.AES_EAX:
            return SymCipher_EAX(args, sym_key)
        if index == CipherTypes.AES_GCM:
            return SymCipher_GCM(args, sym_key)
        if index == CipherTypes.AES_SIV:
            return SymCipher_SIV(args, sym_key)
        if index == CipherTypes.AES_OCB:
            return SymCipher_OCB(args, sym_key)
        if index == CipherTypes.CHACHA20:
            return SymCipher_ChaCha20(args, sym_key)
        
        # If index is wrong, return GCM by default
        return SymCipher_GCM(args, sym_key)
    
    @staticmethod
    def get_cipher_object(index : int, sym_key : bytes, nonce : bytes | None = None):
        if index == CipherTypes.AES_CCM:
            return AES.new(sym_key, AES.MODE_CCM, nonce=nonce)
        if index == CipherTypes.AES_EAX:
            return AES.new(sym_key, AES.MODE_EAX, nonce=nonce)
        if index == CipherTypes.AES_GCM:
            return AES.new(sym_key, AES.MODE_GCM, nonce=nonce)
        if index == CipherTypes.AES_SIV:    # For SIV mode nonce must be assigned manually
            if nonce is None:   # Check whether function was called from decryptor (so with an already specified nonce)
                nonce = get_random_bytes(CipherTypes.__SIV_MODE_NONCE_SIZE)
            return AES.new(sym_key, AES.MODE_SIV, nonce=nonce)
        if index == CipherTypes.AES_OCB:
            return AES.new(sym_key, AES.MODE_OCB, nonce=nonce)
        if index == CipherTypes.CHACHA20:
            return ChaCha20_Poly1305.new(key=sym_key, nonce=nonce)
        
        raise ValueError("index is not in the required value interval")   


class SymCipher:
    __cipher_type : int
    __key : bytes
    __timestamp_tolerance : int
    __rekeyer : Rekeyer
    __debug_flag : bool

    __latency_meter_enc : LatencyMeter | None
    __latency_meter_dec : LatencyMeter | None


    def __init__(self, args, cipher_type : int, sym_key : bytes) -> None:
        self.__cipher_type = cipher_type
        self.__key = sym_key
        self.__timestamp_tolerance = 1      # Tolerance for timestamp deviation (in seconds)

        if args is not None:
            if args.debug:
                self.__debug_flag = True
            else:
                self.__debug_flag = False
            
            if args.disable_rekeying:
                self.__rekeyer = RekeyerDisabler()
            else:
                self.__rekeyer = Rekeyer(args.set_rekey_interval, debug_flag=self.__debug_flag)

            if args.disable_replay_resistance:
                self.__timestamp_tolerance = -1
            else:
                self.__timestamp_tolerance = args.set_timestamp_tolerance

            if args.measure_perf:
                self.__latency_meter_enc = LatencyMeter()
                self.__latency_meter_dec = LatencyMeter()
            else:
                self.__latency_meter_enc = self.__latency_meter_dec = None

        else:                               # Case when args is None (external debug/tests)
            self.__rekeyer = RekeyerDisabler()
            self.__timestamp_tolerance = -1
            self.__debug_flag = True

    def get_latency_meters(self):
        if self.__latency_meter_enc is None or self.__latency_meter_dec is None:
            return None
        return (self.__latency_meter_enc.get_average_latency(), self.__latency_meter_dec.get_average_latency())

    def __update_key(self, *, called_before_send : bool):
        if not isinstance(self.__rekeyer, RekeyerDisabler):
            rekeyer_key = self.__rekeyer.get_new_key(called_before_send=called_before_send)
            if rekeyer_key is not None and rekeyer_key != self.__key:
                self.__key = rekeyer_key
                if self.__debug_flag is True:
                    print("\t* New symmetric key applied! *")
                    print("\tNew key: ", rekeyer_key.hex(' '))

    def __get_cipher(self, sym_key : bytes | None = None, nonce : bytes | None = None):
        if (sym_key is None) != (nonce is None):
            raise TypeError("Function must be called with either 0 or 2 arguments!")

        if sym_key is None:
            return CipherTypes.get_cipher_object(self.__cipher_type, self.__key, None)
        return CipherTypes.get_cipher_object(self.__cipher_type, sym_key, nonce)
    
    def get_sym_key(self):
        return self.__key.hex(" ")

    def __encrypt_and_digest(self, msg : bytes):
        cipher = self.__get_cipher()

        nonce = cipher.nonce

        timestamp = int(time()).to_bytes(4)
        cipher.update(timestamp)

        if isinstance(cipher, ChaCha20Poly1305Cipher):
            if self.__latency_meter_enc is not None:
                (ciphertext, MAC_tag) = self.__latency_meter_enc.measure_latency(lambda: cipher.encrypt_and_digest(msg))
            else:
                (ciphertext, MAC_tag) = cipher.encrypt_and_digest(msg)  # ChaCha20 is a stream cipher => no padding required
        else:
            if self.__latency_meter_enc is not None:
                (ciphertext, MAC_tag) = self.__latency_meter_enc.measure_latency(lambda: cipher.encrypt_and_digest(pad(msg, AES.block_size)))
            else:
                (ciphertext, MAC_tag) = cipher.encrypt_and_digest(pad(msg, AES.block_size))

        return (nonce, timestamp, ciphertext, MAC_tag)

    def encrypt_and_digest(self, msg : bytes, is_reset_msg : bool = False):
        self.__update_key(called_before_send=True) # Update key from rekeyer (if rekeying took place)

        (nonce, timestamp, ciphertext, MAC_tag) = self.__encrypt_and_digest(msg)
        
        enc_data = Formatter.pack(self.__rekeyer.get_send_state(is_reset_msg), nonce, timestamp, ciphertext, MAC_tag, self.__rekeyer.get_own_public_secret())

        return enc_data
    
    def __decrypt_and_verify(self, nonce, timestamp_msg, ciphertext, MAC_tag, sym_key : bytes):
        cipher = self.__get_cipher(sym_key, nonce)
        
        timestamp_now = int(time())

        try:
            cipher.update(timestamp_msg)

            if isinstance(cipher, ChaCha20Poly1305Cipher):
                if self.__latency_meter_dec is not None:
                    msg = self.__latency_meter_dec.measure_latency(lambda: cipher.decrypt_and_verify(ciphertext, MAC_tag))
                else:
                    msg = cipher.decrypt_and_verify(ciphertext, MAC_tag)
            else:
                if self.__latency_meter_dec is not None:
                    msg = self.__latency_meter_dec.measure_latency(lambda: unpad(cipher.decrypt_and_verify(ciphertext, MAC_tag), AES.block_size))
                else:
                    msg = unpad(cipher.decrypt_and_verify(ciphertext, MAC_tag), AES.block_size)
        
            if self.__timestamp_tolerance > -1:  # Check if replay resistance is disabled
                if(abs(timestamp_now - int.from_bytes(timestamp_msg)) > self.__timestamp_tolerance):    # Verify timestamp
                    raise TimeoutError("timestamp different")
                
            return msg
        except ValueError:
            raise
        
    def decrypt_and_verify(self, enc_msg : bytes):
        (rekey_flag, nonce, timestamp_msg, ciphertext, MAC_tag, shared_secret) = Formatter.unpack(enc_msg)

        self.__rekeyer.handle_rekey(self.__key, rekey_flag, shared_secret)
        self.__update_key(called_before_send=False) # Update key from rekeyer (if rekeying took place)

        try:
            return self.__decrypt_and_verify(nonce, timestamp_msg, ciphertext, MAC_tag, self.__key)
        except ValueError:  # Maybe peer has failed key exchange; try decrypting with old key
            old_sym_key = self.__rekeyer.get_old_key()
            if old_sym_key is not None:
                try:
                    data = self.__decrypt_and_verify(nonce, timestamp_msg, ciphertext, MAC_tag, old_sym_key)
                    self.__rekeyer.set_fail_flag()
                    if self.__debug_flag:
                        print("*** Rekeying failed! Reverting to old key! ***")
                    self.__key = old_sym_key
                    return data
                except ValueError:      # If old key couldn't decrypt data either
                    raise
            else:   # If old_sym_key is None:
                raise
        except TimeoutError as e:
            print("!!! Timestamp is different !!!")
            print("\t", e)
            raise ValueError(e.strerror)


class SymCipher_CCM(SymCipher):
    def __init__(self, args, sym_key : bytes) -> None:
        super().__init__(args, CipherTypes.AES_CCM, sym_key)
 
    def encrypt_and_digest(self, msg : bytes, is_reset_msg : bool = False):
        return super().encrypt_and_digest(msg, is_reset_msg) 

    def decrypt_and_verify(self, enc_msg: bytes):
        return super().decrypt_and_verify(enc_msg)


class SymCipher_EAX(SymCipher):
    def __init__(self, args, sym_key: bytes) -> None:
        super().__init__(args, CipherTypes.AES_EAX, sym_key)

    def encrypt_and_digest(self, msg : bytes, is_reset_msg : bool = False):
        return super().encrypt_and_digest(msg, is_reset_msg)

    def decrypt_and_verify(self, enc_msg: bytes):
        return super().decrypt_and_verify(enc_msg)


class SymCipher_GCM(SymCipher):
    def __init__(self, args, sym_key: bytes) -> None:
        super().__init__(args, CipherTypes.AES_GCM, sym_key)

    def encrypt_and_digest(self, msg : bytes, is_reset_msg : bool = False):
        return super().encrypt_and_digest(msg, is_reset_msg)

    def decrypt_and_verify(self, enc_msg: bytes):
        return super().decrypt_and_verify(enc_msg)


class SymCipher_SIV(SymCipher):
    def __init__(self, args, sym_key: bytes) -> None:
        super().__init__(args, CipherTypes.AES_SIV, sym_key)

    def encrypt_and_digest(self, msg : bytes, is_reset_msg : bool = False):
        return super().encrypt_and_digest(msg, is_reset_msg)

    def decrypt_and_verify(self, enc_msg: bytes):
        return super().decrypt_and_verify(enc_msg)


class SymCipher_OCB(SymCipher):
    def __init__(self, args, sym_key: bytes) -> None:
        super().__init__(args, CipherTypes.AES_OCB, sym_key)

    def encrypt_and_digest(self, msg : bytes, is_reset_msg : bool = False):
        return super().encrypt_and_digest(msg, is_reset_msg)

    def decrypt_and_verify(self, enc_msg: bytes):
        return super().decrypt_and_verify(enc_msg)


class SymCipher_ChaCha20(SymCipher):
    def __init__(self, args, sym_key: bytes) -> None:
        super().__init__(args, CipherTypes.CHACHA20, sym_key)

    def encrypt_and_digest(self, msg : bytes, is_reset_msg : bool = False):
        return super().encrypt_and_digest(msg, is_reset_msg)

    def decrypt_and_verify(self, enc_msg: bytes):
        return super().decrypt_and_verify(enc_msg)