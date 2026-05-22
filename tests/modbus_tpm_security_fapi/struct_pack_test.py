import struct
import random

N = 1

data1 = random.randbytes(16)
data2 = random.randint(0, 0xFFFF_FFFF)
data3 = random.randbytes(N*16)
data4 = random.randbytes(16)
# extra_data = random.randbytes(32)
extra_data = b""

fmt1 = f'!16sI{N*16}s16s'
fmt2 = f'!32s'

print("Format length: ", struct.calcsize(fmt1), "\n")

packed_data = struct.pack(fmt1, data1, data2, data3, data4)

print("Packed data (first round): ", packed_data)

array = bytearray(packed_data)
array.extend(b'\x00' * struct.calcsize(fmt2))

struct.pack_into(fmt2, array, len(packed_data), extra_data)

print("Packed data (2nd round): ", array)

extra_data_unpk = struct.unpack_from(fmt2, array, struct.calcsize(fmt1))
data1_unpk, data2_unpk, data3_unpk, data4_unpk = struct.unpack_from(fmt1, array)

print("\nUnpacked data: ")
print("data1_unpk = ", data1_unpk)
print("data2_unpk = ", data2_unpk)
print("data3_unpk = ", data3_unpk)
print("data4_unpk = ", data4_unpk)
print("extra_data_unpk = ", extra_data_unpk)
