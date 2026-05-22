import datetime
import timeit
from typing import Callable, TypeVar

T = TypeVar("T")


# Function for exporting measured data to file
def export_to_file_key_exchange(key_exchange_latency):
    with open("latency_output.txt", "a", newline="") as output_file:
        output_file.write("#############################################\n")
        output_file.write(datetime.datetime.now().isoformat(' ', 'seconds') + "\n")
        output_file.write(f"Key exchange latency:     \t{key_exchange_latency}\n")
        # output_file.write(f"Encrypt & digest latency: \t{encrpyt_average_latency}\n")
        # output_file.write(f"Decrypt & verify latency: \t{decrypt_average_latency}\n\n")


# Function for exporting measured data to file
def export_to_file_sym_cipher(encrpyt_average_latency, decrypt_average_latency):
    with open("latency_output.txt", "a", newline="") as output_file:
        # output_file.write("#############################################\n")
        # output_file.write(datetime.datetime.now().isoformat(' ', 'seconds') + "\n")
        # output_file.write(f"Key exchange latency:     \t{key_exchange_latency}\n")
        output_file.write(f"Encrypt & digest latency: \t{encrpyt_average_latency}\n")
        output_file.write(f"Decrypt & verify latency: \t{decrypt_average_latency}\n\n")


class LatencyMeter:
    __average = 0
    __size = 0


    # Function for adding a new value to an existing average of "size" numbers
    def __add_to_average(self, add_value):
        if(self.__average == 0):
            self.__average = add_value
        else:
            self.__average = self.__average + ((add_value - self.__average) / (self.__size + 1))
        self.__size += 1
    
    def measure_latency(self, fun : Callable[[], T]) -> T:
        result = fun()

        timer = timeit.Timer(fun) # type: ignore
        loop_num, _ = timer.autorange()
        samples = timer.repeat(number=loop_num)
        best = min(samples) / loop_num

        self.__add_to_average(best)

        return result

    def get_average_latency(self):
        return self.__average

