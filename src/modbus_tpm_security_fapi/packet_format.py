import struct
from enum import IntEnum


class Formatter(IntEnum):
    __TIMESTAMP_SIZE = 4
    __MAC_TAG_SIZE = 16
    __NEW_SHRD_SCRT_SIZE = 32

    __HEADER_FORMAT = "!?BB"    # [1 byte bool, 1 byte unsigned int, 1 byte unsigned int]
    __HEADER_LENGTH = struct.calcsize(__HEADER_FORMAT)

    __FOOTER_FORMAT = f"!{__NEW_SHRD_SCRT_SIZE}s"
    __FOOTER_LENGTH = struct.calcsize(__FOOTER_FORMAT)

    __TOTAL_FIXED_SIZE_NORM = __HEADER_LENGTH + __TIMESTAMP_SIZE + __MAC_TAG_SIZE
    __TOTAL_FIXED_SIZE_SHRD_SCRT = __TOTAL_FIXED_SIZE_NORM + __FOOTER_LENGTH

    @staticmethod
    def __pack_header(packed_data : bytearray, has_footer : bool, rekey_flag : int, nonce_size : int):
        struct.pack_into(Formatter.__HEADER_FORMAT, packed_data, 0, has_footer, rekey_flag, nonce_size)
        return packed_data
    
    @staticmethod
    def __pack_footer(packed_data : bytearray, shared_secret : bytes):
        if shared_secret == b'':
            return packed_data

        struct.pack_into(Formatter.__FOOTER_FORMAT, packed_data, len(packed_data) - Formatter.__FOOTER_LENGTH, shared_secret)
        return packed_data
    
    @staticmethod
    def __pack_payload(format : str, packed_data : bytearray, timestamp : bytes, nonce : bytes, ciphertext : bytes, MAC_tag : bytes):
        struct.pack_into(format, packed_data, Formatter.__HEADER_LENGTH,
                        timestamp, nonce, ciphertext, MAC_tag)
        
        return packed_data

    @staticmethod
    def pack(rekey_flag : int, nonce : bytes, timestamp : bytes, ciphertext : bytes, MAC_tag : bytes, shared_secret : bytes):
        ciphertext_len = len(ciphertext)
        nonce_len = len(nonce)

        if shared_secret == b'':
            packet_size = Formatter.__TOTAL_FIXED_SIZE_NORM + ciphertext_len + nonce_len
            has_footer = False
        else:
            packet_size = Formatter.__TOTAL_FIXED_SIZE_SHRD_SCRT + ciphertext_len + nonce_len
            has_footer = True

        packed_data = bytearray(packet_size)

        payload_fmt = f"!{Formatter.__TIMESTAMP_SIZE}s{nonce_len}s{ciphertext_len}s{Formatter.__MAC_TAG_SIZE}s"

        packed_data = Formatter.__pack_header(packed_data, has_footer, rekey_flag, nonce_len)                   # Pack header
        packed_data = Formatter.__pack_payload(payload_fmt, packed_data, timestamp, nonce, ciphertext, MAC_tag) # Pack main payload
        packed_data = Formatter.__pack_footer(packed_data, shared_secret)                                       # Pack footer
        
        return bytes(packed_data)

    @staticmethod
    def __unpack_header(packed_data : bytes) -> tuple[bool, int, int]:
        return struct.unpack_from(Formatter.__HEADER_FORMAT, packed_data, 0)
    
    @staticmethod
    def __unpack_footer(packed_data : bytes) -> bytes:
        shared_secret : tuple[bytes] = struct.unpack_from(Formatter.__FOOTER_FORMAT, packed_data, len(packed_data) - Formatter.__FOOTER_LENGTH)
        return shared_secret[0]
    
    @staticmethod
    def __unpack_payload(format : str, packed_data : bytes):
        return struct.unpack_from(format, packed_data, Formatter.__HEADER_LENGTH)
    
    @staticmethod
    def unpack(packed_data : bytes) -> tuple[int, bytes, bytes, bytes, bytes, bytes]:
        has_footer, rekey_flag, nonce_len = Formatter.__unpack_header(packed_data)                # Unpack header
        packet_size = len(packed_data)

        if has_footer is True:
            shared_secret = Formatter.__unpack_footer(packed_data)                                # Unpack footer
            ciphertext_len = packet_size - nonce_len - Formatter.__TOTAL_FIXED_SIZE_SHRD_SCRT
        else:
            shared_secret = b''
            ciphertext_len = packet_size - nonce_len - Formatter.__TOTAL_FIXED_SIZE_NORM
        
        payload_fmt = f"!{Formatter.__TIMESTAMP_SIZE}s{nonce_len}s{ciphertext_len}s{Formatter.__MAC_TAG_SIZE}s"

        return (rekey_flag, ) + Formatter.__unpack_payload(payload_fmt, packed_data) + (shared_secret, ) # Unpack payload & return
        