import socket
import threading
from src.modbus_tpm_security_fapi.gateway import gateway_common
from src.modbus_tpm_security_fapi import utils
from time import sleep
from src.modbus_tpm_security_fapi.key_exchange import DH_key_exchange
from src.modbus_tpm_security_fapi.perf_measure import latency_measure
from src.modbus_tpm_security_fapi.parse_args import parse_args_main
from src.modbus_tpm_security_fapi.sym_cipher import SymCipher, CipherTypes
from src.modbus_tpm_security_fapi.netcomm import NetComm


exit_flag = False
reset_flag = False

debug_level = 0


# source is the client | dest is the server gateway
def forward_source_dest(communicator_source : NetComm, communicator_dest : NetComm, cipher : SymCipher, latency_meter : latency_measure.LatencyMeter | None = None):
    global reset_flag

    while not exit_flag and not reset_flag:
        try:
            data = communicator_source.receive()
            if not data:
                raise ConnectionError
        except TimeoutError:
            if exit_flag or reset_flag:
                break
            continue
        except ConnectionError:
            reset_flag = True
            print("Source socket (client) error or disconnection. Resetting connection...")
            break

        if debug_level >= 1:
            print("\nReceived from source: ", data)

        if latency_meter is not None:
            enc_data = latency_meter.measure_latency(lambda: cipher.encrypt_and_digest(data))
        else:
            enc_data = cipher.encrypt_and_digest(data)

        try:
            communicator_dest.send(enc_data)

            if debug_level >= 1:
                print("Sent to dest: ", enc_data)
            
            if debug_level >= 2:
                print("Used key: ", cipher.get_sym_key())
        except(BrokenPipeError):
            reset_flag = True
            print("*** Destination socket (server gateway) is broken (BrokenPipeError). Resetting connection... ***")

    if exit_flag or reset_flag:
        try:
            communicator_dest.send(cipher.encrypt_and_digest(gateway_common.SOCKET_RESET_MESSAGE, is_reset_msg=True))
        except(BrokenPipeError):
            print("*** Unable to send resset message to destination socket (server gateway) - BrokenPipeError ***")



# source is the client | dest is the server gateway
def forward_dest_source(communicator_source : NetComm, communicator_dest : NetComm, cipher : SymCipher, latency_meter : latency_measure.LatencyMeter | None = None):
    global reset_flag

    while not exit_flag and not reset_flag:
        try:
            enc_data = communicator_dest.receive()
            if not enc_data:
                raise ConnectionError
        except TimeoutError:
            if exit_flag or reset_flag:
                break
            continue
        except ConnectionError:
            reset_flag = True
            print("Destination socket (server gateway) error or disconnection. Resetting connection...")
            communicator_dest.send(cipher.encrypt_and_digest(gateway_common.SOCKET_RESET_MESSAGE, is_reset_msg=True))
            break

        if debug_level >= 1:
            print("\nReceived from dest: ", enc_data)

        if debug_level >= 2:
            print("Used key: ", cipher.get_sym_key())

        try:
            if latency_meter is not None:
                data = latency_meter.measure_latency(lambda: cipher.decrypt_and_verify(enc_data))
            else:
                data = cipher.decrypt_and_verify(enc_data)

            if debug_level >= 1:
                print("Sent to source: ", data)

            if(data == gateway_common.SOCKET_RESET_MESSAGE):
                reset_flag = True
                print("Reset message received!")
                break

            communicator_source.send(data)
        except ValueError:
            print("**** !!! Message tampered or key is incorrect !!! ****")
        except BrokenPipeError:
            reset_flag = True
            print("*** Source socket (client) is broken (BrokenPipeError). Resetting connection... ***")


def handle_transfer(args, source_socket : socket.socket, dest_socket : socket.socket, sym_key : bytes):
    cipher = CipherTypes.get_symcipher_from_args(args, sym_key)   # Shared encryptor/decryptor object for the two threads
    communicator_source = NetComm(source_socket, header_format=gateway_common.MODBUS_TCP_HEADER_FORMAT, length_index=gateway_common.MODBUS_TCP_PAYLOAD_LENGHTH_INDEX,
                                  headerless_send=True, header_receive=True)
    communicator_dest = NetComm(dest_socket)

    latency_meter_enc = latency_meter_dec = None
    if args.measure_perf:
        latency_meter_enc = latency_measure.LatencyMeter()
        latency_meter_dec = latency_measure.LatencyMeter()

    forward_source_dest_thread = threading.Thread(target = forward_source_dest, args = (communicator_source, communicator_dest, cipher, latency_meter_enc))
    forward_dest_source_thread = threading.Thread(target = forward_dest_source, args = (communicator_source, communicator_dest, cipher, latency_meter_dec))

    forward_source_dest_thread.start()
    forward_dest_source_thread.start()

    # Main thread waits here after starting data forwarding child threads
    # Wait for KeyboardInterrupt (Ctrl+C)
    try:
        while forward_source_dest_thread.is_alive() or forward_dest_source_thread.is_alive():
            sleep(1)
    except(KeyboardInterrupt):
        global exit_flag
        exit_flag = True
        print("Closing program at user request (Ctrl+C)...")

    forward_source_dest_thread.join()
    forward_dest_source_thread.join()

    print("Threads closed successfully.")

    if args.measure_perf and (latency_meter_enc is not None and latency_meter_dec is not None):
        latency_measure.export_to_file_sym_cipher(latency_meter_enc.get_average_latency(), latency_meter_enc.get_average_runs(),
                                                   latency_meter_dec.get_average_latency(), latency_meter_dec.get_average_runs())


def main(): 
    host_ip = utils.get_host_ip()   # host_ip = '192.168.50.80'
    host_port = 502

    source_ip = '192.168.50.241'
    source_port = 502

    dest_ip = '192.168.50.81'
    dest_port = 502

    # Handle run arguments
    args = parse_args_main(__file__)

    if args.host:
        host_ip = args.host
    if args.host_ip:
        host_ip = args.host_ip
    if args.dest:
        dest_ip = args.dest
    if args.dest_ip:
        dest_ip = args.dest_ip

    global debug_level
    if args.v:
        debug_level = 1
    elif args.vv:
        debug_level = 2
    elif args.vvv:
        debug_level = 3

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)     # Set TCP_NODELAY
    server_socket.bind((host_ip, host_port))
    server_socket.listen(5)

    while not exit_flag:
        global reset_flag
        reset_flag = False

        print(f"[*] Listening on {host_ip}:{host_port}")

        dest_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dest_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)     # Set TCP_NODELAY
        dest_socket.connect((dest_ip, dest_port))
        print(f"[*] Established connection to server(destination): {(dest_ip, dest_port)}")
        
        if args.measure_perf:
            latency_meter = latency_measure.LatencyMeter()
            # do key exchange here
            sym_key = latency_meter.measure_latency(lambda: DH_key_exchange(dest_socket))  # for server gateway use 'source_socket' | for client gateway use 'dest_socket'
            latency_measure.export_to_file_key_exchange(latency_meter.get_average_latency(), latency_meter.get_average_runs())
        else:
            # do key exchange here
            sym_key = DH_key_exchange(dest_socket)                                         # for server gateway use 'source_socket' | for client gateway use 'dest_socket'

        # Connect to client endpoint (SCADA server)
        source_socket, source_addr = server_socket.accept()
        print(f"[*] Accepted connection from client(source): {source_addr}")

        # If sym_key generated & transferred successfully proceed with normal data handling
        if(sym_key != None):
            # Set sockets to non-blocking mode
            source_socket.settimeout(gateway_common.SOCKET_TIMEOUT)
            dest_socket.settimeout(gateway_common.SOCKET_TIMEOUT)

            handle_transfer(args, source_socket, dest_socket, sym_key)
        else:
            print("Key exchange error")
        
        # Try to shutdown sockets and then close them
        try:
            source_socket.shutdown(socket.SHUT_RDWR)
        except(OSError):
            print("*** Source socket (client) already closed at the other end ***")

        try:
            dest_socket.shutdown(socket.SHUT_RDWR)
        except(OSError):
            print("*** Destination socket (server gateway) already closed at the other end ***")

        source_socket.close()
        dest_socket.close()

    print("Program closed successfully!")


if __name__ == "__main__":
    main()
