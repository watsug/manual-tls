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
    
    def connect(self) -> None:
        self.s = socket.create_connection((self.host, self.port), self.timeout)

    def sendall(self, data) -> None:
        self.s.sendall(data)

    def recv(self, bufsize: int) -> bytes:
        return self.s.recv(bufsize)
    

print(f"Connecting to {HOST}:{PORT}")
comm = SocektComm(HOST, PORT, TIMEOUT)
comm.connect()

tls = ManualTls(comm)
tls.establish()
resp = tls.transmit(REQUEST)
print(resp.decode(errors='ignore'))
tls.transmit(None)