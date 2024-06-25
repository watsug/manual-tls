import logging
import socket
from manual_tls.manual_tls import ManualComm, ManualTls, CertificateType

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

HOST = "habr.com"
PORT = 443
TIMEOUT = 10
REQUEST = b"HEAD /ru/company/habr/blog/522330/ HTTP/1.1\r\nHost: habr.com\r\nConnection: close\r\n\r\n"

class SocketComm(ManualComm):
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


logging.info(f"Connecting to {HOST}:{PORT}")
comm = SocketComm(HOST, PORT, TIMEOUT)
comm.connect()


tls = ManualTls()
client_cert_type = CertificateType.X509
server_cert_type = CertificateType.X509
tls.initialize(comm, client_cert_type, server_cert_type)

pub_key_x, pub_key_y = tls.load_client_key("./certs/watsug.key")
if client_cert_type == CertificateType.X509:
    tls.load_client_certificate("./certs/watsug.crt")

logging.info(f"pub_key_x: {pub_key_x.hex()}")
logging.info(f"pub_key_y: {pub_key_y.hex()}")

tls.establish()
resp = tls.transmit(REQUEST)
logging.info(resp.decode(errors='ignore'))
tls.transmit(None)
