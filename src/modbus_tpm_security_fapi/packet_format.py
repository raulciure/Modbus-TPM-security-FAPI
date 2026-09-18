import struct


class Formatter:
    _MAC_TAG_SIZE = 16
    _NEW_SHRD_SCRT_SIZE = 32

    _FOOTER_FORMAT = f"!{_NEW_SHRD_SCRT_SIZE}s"
    _FOOTER_LENGTH = struct.calcsize(_FOOTER_FORMAT)

    def _pack_footer(self, packed_data : bytearray, shared_secret : bytes):
        if shared_secret == b'':
            return packed_data

        struct.pack_into(self._FOOTER_FORMAT, packed_data, len(packed_data) - self._FOOTER_LENGTH, shared_secret)
        return packed_data

    def _unpack_footer(self, packed_data : bytes) -> bytes:
        shared_secret : tuple[bytes] = struct.unpack_from(self._FOOTER_FORMAT, packed_data, len(packed_data) - self._FOOTER_LENGTH)
        return shared_secret[0]


class TimestampFormatter(Formatter):
    _TIMESTAMP_SIZE = 4

    _HEADER_FORMAT = "!?BB"    # [1 byte bool, 1 byte unsigned int, 1 byte unsigned int]
    _HEADER_LENGTH = struct.calcsize(_HEADER_FORMAT)

    _TOTAL_FIXED_SIZE_NORM = _HEADER_LENGTH + _TIMESTAMP_SIZE + Formatter._MAC_TAG_SIZE
    _TOTAL_FIXED_SIZE_SHRD_SCRT = _TOTAL_FIXED_SIZE_NORM + Formatter._FOOTER_LENGTH

    def __pack_header(self, packed_data : bytearray, has_footer : bool, rekey_flag : int, nonce_size : int):
        struct.pack_into(self._HEADER_FORMAT, packed_data, 0, has_footer, rekey_flag, nonce_size)
        return packed_data
    
    def __pack_payload(self, format : str, packed_data : bytearray, timestamp : bytes, nonce : bytes, ciphertext : bytes, MAC_tag : bytes):
        struct.pack_into(format, packed_data, self._HEADER_LENGTH,
                        timestamp, nonce, ciphertext, MAC_tag)
        
        return packed_data

    def pack(self, rekey_flag : int, timestamp : bytes, nonce : bytes, ciphertext : bytes, MAC_tag : bytes, shared_secret : bytes):
        ciphertext_len = len(ciphertext)
        nonce_len = len(nonce)

        if shared_secret == b'':
            packet_size = self._TOTAL_FIXED_SIZE_NORM + ciphertext_len + nonce_len
            has_footer = False
        else:
            packet_size = self._TOTAL_FIXED_SIZE_SHRD_SCRT + ciphertext_len + nonce_len
            has_footer = True

        packed_data = bytearray(packet_size)

        payload_fmt = f"!{self._TIMESTAMP_SIZE}s{nonce_len}s{ciphertext_len}s{Formatter._MAC_TAG_SIZE}s"

        packed_data = self.__pack_header(packed_data, has_footer, rekey_flag, nonce_len)                        # Pack header
        packed_data = self.__pack_payload(payload_fmt, packed_data, timestamp, nonce, ciphertext, MAC_tag)      # Pack main payload
        packed_data = super()._pack_footer(packed_data, shared_secret)                                          # Pack footer
        
        return bytes(packed_data)

    def __unpack_header(self, packed_data : bytes) -> tuple[bool, int, int]:
        return struct.unpack_from(self._HEADER_FORMAT, packed_data, 0)
    
    def __unpack_payload(self, format : str, packed_data : bytes):
        return struct.unpack_from(format, packed_data, self._HEADER_LENGTH)

    def unpack(self, packed_data : bytes) -> tuple[int, bytes, bytes, bytes, bytes, bytes]:
        has_footer, rekey_flag, nonce_len = self.__unpack_header(packed_data)                   # Unpack header
        packet_size = len(packed_data)

        if has_footer is True:
            shared_secret = super()._unpack_footer(packed_data)                                 # Unpack footer
            ciphertext_len = packet_size - nonce_len - self._TOTAL_FIXED_SIZE_SHRD_SCRT
        else:
            shared_secret = b''
            ciphertext_len = packet_size - nonce_len - self._TOTAL_FIXED_SIZE_NORM
        
        payload_fmt = f"!{self._TIMESTAMP_SIZE}s{nonce_len}s{ciphertext_len}s{Formatter._MAC_TAG_SIZE}s"

        return (rekey_flag, ) + self.__unpack_payload(payload_fmt, packed_data) + (shared_secret, )     # Unpack payload & return


class SequenceNumberFormatter(Formatter):
    __SEQ_NUM_SIZE = 8

    __HEADER_FORMAT = "!?B"    # [1 byte bool, 1 byte unsigned int, 1 byte unsigned int]
    __HEADER_LENGTH = struct.calcsize(__HEADER_FORMAT)

    __TOTAL_FIXED_SIZE_NORM = __HEADER_LENGTH + __SEQ_NUM_SIZE + Formatter._MAC_TAG_SIZE
    __TOTAL_FIXED_SIZE_SHRD_SCRT = __TOTAL_FIXED_SIZE_NORM + Formatter._FOOTER_LENGTH

    def __pack_header(self, packed_data : bytearray, has_footer : bool, rekey_flag : int):
        struct.pack_into(self.__HEADER_FORMAT, packed_data, 0, has_footer, rekey_flag)
        return packed_data
    
    def __pack_payload(self, format : str, packed_data : bytearray, seq_num : bytes, ciphertext : bytes, MAC_tag : bytes):
        struct.pack_into(format, packed_data, self.__HEADER_LENGTH,
                        seq_num, ciphertext, MAC_tag)
        return packed_data

    def pack(self, rekey_flag : int, seq_num : bytes, ciphertext : bytes, MAC_tag : bytes, shared_secret : bytes):
        ciphertext_len = len(ciphertext)

        if shared_secret == b'':
            packet_size = self.__TOTAL_FIXED_SIZE_NORM + ciphertext_len
            has_footer = False
        else:
            packet_size = self.__TOTAL_FIXED_SIZE_SHRD_SCRT + ciphertext_len
            has_footer = True

        packed_data = bytearray(packet_size)

        payload_fmt = f"!{self.__SEQ_NUM_SIZE}s{ciphertext_len}s{Formatter._MAC_TAG_SIZE}s"

        packed_data = self.__pack_header(packed_data, has_footer, rekey_flag)                           # Pack header
        packed_data = self.__pack_payload(payload_fmt, packed_data, seq_num, ciphertext, MAC_tag)       # Pack main payload
        packed_data = super()._pack_footer(packed_data, shared_secret)                                  # Pack footer
        
        return bytes(packed_data)
    
    def __unpack_header(self, packed_data : bytes) -> tuple[bool, int]:
        return struct.unpack_from(self.__HEADER_FORMAT, packed_data, 0)
    
    def __unpack_payload(self, format : str, packed_data : bytes):
        return struct.unpack_from(format, packed_data, self.__HEADER_LENGTH)
    
    def unpack(self, packed_data : bytes) -> tuple[int, bytes, bytes, bytes, bytes]:
        has_footer, rekey_flag = self.__unpack_header(packed_data)                              # Unpack header
        packet_size = len(packed_data)

        if has_footer is True:
            shared_secret = super()._unpack_footer(packed_data)                                 # Unpack footer
            ciphertext_len = packet_size - self.__TOTAL_FIXED_SIZE_SHRD_SCRT
        else:
            shared_secret = b''
            ciphertext_len = packet_size - self.__TOTAL_FIXED_SIZE_NORM
        
        payload_fmt = f"!{self.__SEQ_NUM_SIZE}s{ciphertext_len}s{Formatter._MAC_TAG_SIZE}s"

        return (rekey_flag, ) + self.__unpack_payload(payload_fmt, packed_data) + (shared_secret, )     # Unpack payload & return