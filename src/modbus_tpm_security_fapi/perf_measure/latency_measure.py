import datetime
import timeit
import time
from typing import Callable, TypeVar

T = TypeVar("T")

OUTPUT_FILE = "latency_output.txt"

# Function for exporting measured data to file
def export_to_file_key_exchange(key_exchange_latency, avg_num_of_runs):
    with open(OUTPUT_FILE, "a", newline="") as output_file:
        output_file.write("#############################################\n")
        output_file.write(datetime.datetime.now().isoformat(' ', 'seconds') + "\n")
        output_file.write(f"Key exchange latency:     \t{key_exchange_latency}s \t| Average runs: \t{avg_num_of_runs}\n")


# Function for exporting measured data to file
def export_to_file_sym_cipher(encrpyt_average_latency, enc_avg_num_of_runs, decrypt_average_latency, dec_avg_num_of_runs):
    with open(OUTPUT_FILE, "a", newline="") as output_file:
        output_file.write(f"Encrypt & digest latency: \t{encrpyt_average_latency}s \t| Average runs: \t{enc_avg_num_of_runs}\n")
        output_file.write(f"Decrypt & verify latency: \t{decrypt_average_latency}s \t| Average runs: \t{dec_avg_num_of_runs}\n\n")


class LatencyMeter:
    __average : float = 0
    __average_runs : float = 0
    __size = 0


    def __add_to_average(self, add_value : float, number_of_runs : int):      # Function for adding a new value to an existing average of "size" numbers
        if self.__average == 0:
            self.__average = add_value
            self.__average_runs = number_of_runs
        else:
            self.__average = self.__average + ((add_value - self.__average) / (self.__size + 1))
            self.__average_runs = self.__average_runs + ((number_of_runs - self.__average_runs) / (self.__size + 1))
        self.__size += 1
    
    def measure_latency(self, fun : Callable[[], T], time_budget = 0.1, safety_factor = 0.6) -> T:
        t_init_start = time.perf_counter()
        result = fun()
        t_init_taken = time.perf_counter() - t_init_start

        if t_init_taken >= time_budget:
            self.__add_to_average(t_init_taken, 1)
            return result

        timer = timeit.Timer(fun) # type: ignore

        deadline_t = time.perf_counter() + time_budget      # Calculate deadline time for finishing current measurment

        t_one = timer.timeit(number=1)                      # Run once to get an estimate of time required for one run

        remaining_t = deadline_t - time.perf_counter()      # Calculate remaining time based on deadline time and current time
        if remaining_t <= 0:                # If there's no remaining time left, return using only the one measurment already taken
            self.__add_to_average(t_one, 1)
            return result
        
        # Else, estimate the maximum number of loops so that the deadline is not exceeded, using a safety factor
        loop_num = max(1, int((remaining_t * safety_factor) / t_one))       # Use only part of the remaining time to avoid overshoot (i.e. exceeding time_budget)

        t_total = timer.timeit(number=loop_num)

        self.__add_to_average((t_total + t_one) / (loop_num + 1), (loop_num + 1))

        return result

    def get_average_latency(self) -> float:
        return self.__average
    
    def get_average_runs(self) -> float:
        return self.__average_runs
