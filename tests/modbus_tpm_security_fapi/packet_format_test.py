import random
from src.modbus_tpm_security_fapi.packet_format import Formatter


rekey_flag = 0
nonce = random.randbytes(16)
timestamp = random.randbytes(4)
ciphertext = random.randbytes(32)
MAC_tag = random.randbytes(16)
shared_secret = b''
# shared_secret = random.randbytes(32)

print("rekey_flag = ", rekey_flag)
print("nonce = ", nonce)
print("timestamp = ", timestamp)
print("ciphertext = ", ciphertext)
print("MAC_tag = ", MAC_tag)
print("shared_secret = ", shared_secret)

packed_data = Formatter.pack(rekey_flag, nonce, timestamp, ciphertext, MAC_tag, shared_secret)

print("\n---Packed data---")
print(packed_data, "\n")

unpacked_data = Formatter.unpack(packed_data)

print("---Unpacked data---")
print(unpacked_data, "\n")

print("unpacked_rekey_flag = ", unpacked_data[0])
print("unpacked_nonce = ", unpacked_data[1])
print("unpacked_timestamp = ", unpacked_data[2])
print("unpacked_ciphertext = ", unpacked_data[3])
print("unpacked_MAC_tag = ", unpacked_data[4])
print("unpacked_shared_secret = ", unpacked_data[5])


def gen_error():
    print("\nThe packed and unpacked data differ!")
    exit()


if rekey_flag != unpacked_data[0]:
    gen_error()
if nonce != unpacked_data[1]:
    gen_error()
if timestamp != unpacked_data[2]:
    gen_error()
if ciphertext != unpacked_data[3]:
    gen_error()
if MAC_tag != unpacked_data[4]:
    gen_error()
if shared_secret != unpacked_data[5]:
    gen_error()

print("\nIdentical data before packing and after unpacking!")