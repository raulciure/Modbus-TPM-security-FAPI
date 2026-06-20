import struct
import socket


BLIND_RECV_BUFFER_SIZE = 4096

class NetComm:
    __conn_socket : socket.socket
    __header_format : str
    __header_length : int
    __max_msg_size : int
    __length_byte_index : int    # The index in the header where the byte(s) showing the remaining packet size reside
    __blind_operation : bool     # Determines whether data is received/sent blindly from/to peer, without a header size header applied
                                 # Makes irrelevant the following arguments: header_format, length_index, headerless_send, header_receive

    __headerless_send : bool
    __header_receive : bool

    def __init__(self, conn_socket : socket.socket, max_msg_size : int | None = None, *,
                 header_format : str = "!H", length_index : int = 0,
                 headerless_send = False, header_receive = False,
                 blind_operation = False) -> None:
        self.__conn_socket = conn_socket
        self.__header_format = header_format
        self.__header_length = struct.calcsize(self.__header_format)
        self.__length_byte_index = length_index
        
        self.__headerless_send = headerless_send
        self.__header_receive = header_receive

        self.__blind_operation = blind_operation

        if self.__length_byte_index > len(self.__header_format) - 1:            # Check if provided length_index is bigger than the number of elements in the header
            raise ValueError("length_index cannot be bigger than provided packet structure size")

        if max_msg_size is None:
            self.__max_msg_size = 1024 * 1024   # 1 MB max message size (default)
        else:
            self.__max_msg_size = max_msg_size

    def __recv_exact(self, num : int):
        segments = []
        received = 0
        
        while received < num:
            recv_segment = self.__conn_socket.recv(num - received)

            if not recv_segment:
                raise ConnectionError("*** Socket closed before enough data was received! ***")
            
            segments.append(recv_segment)
            received += len(recv_segment)

        return b''.join(segments)
    
    def __recv_blind(self):
       return self.__conn_socket.recv(BLIND_RECV_BUFFER_SIZE)

    def send(self, data : bytes):
        if len(data) > self.__max_msg_size:
            raise ValueError(f"*** Message size exceeded!\nMaximum: {self.__max_msg_size} bytes | Actual: {len(data)} bytes ***")
        
        if self.__blind_operation is True:
            self.__conn_socket.sendall(data)
        else:
            if self.__headerless_send is True:
                self.__conn_socket.sendall(data)
            else:
                header = struct.pack(self.__header_format, len(data))
                self.__conn_socket.sendall(header + data)

    def receive(self):
        if self.__blind_operation is True:
            return self.__recv_blind() 
        else:
            header = self.__recv_exact(self.__header_length)
            payload_size = struct.unpack(self.__header_format, header)[self.__length_byte_index]

            if payload_size > self.__max_msg_size:
                raise ValueError(f"*** Message size exceeded!\nMaximum: {self.__max_msg_size} bytes | Actual: {payload_size} bytes ***")
            
            if self.__header_receive is True:
                return header + self.__recv_exact(payload_size)
            return self.__recv_exact(payload_size)
