import socket
from manual_tls.manual_tls import ManualComm, ManualTls

HOST = "habr.com"
PORT = 443
TIMEOUT = 10
REQUEST = b"HEAD /ru/company/habr/blog/522330/ HTTP/1.1\r\nHost: habr.com\r\nConnection: close\r\n\r\n"

class SocektComm(ManualComm):
    def __init__(self, host, port, timeout) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tx_buf = b""
    
    def connect(self) -> None:
        self.s = socket.create_connection((self.host, self.port), self.timeout)

    def prepare_send(self, data) -> None:
        self.tx_buf = self.tx_buf + data

    def sendall(self, data) -> None:
        self.s.sendall(self.tx_buf + data)
        self.tx_buf = b""

    def recv(self, bufsize: int) -> bytes:
        return self.s.recv(bufsize)
    

print(f"Connecting to {HOST}:{PORT}")
comm = SocektComm(HOST, PORT, TIMEOUT)
comm.connect()

tls = ManualTls(comm)

pub_key_x, pub_key_y = tls.generate_client_key()

tls.establish()
resp = tls.transmit(REQUEST)
print(resp.decode(errors='ignore'))
tls.transmit(None)