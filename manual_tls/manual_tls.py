import logging
from abc import ABC, abstractmethod
from enum import IntEnum
from hashlib import sha256
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from ecdsa import NIST256p, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der

logger = logging.getLogger(__name__)

# in tls 1.3 the version tls 1.2 is sent for better compatibility
LEGACY_TLS_VERSION = b"\x03\x03"
TLS_AES_128_GCM_SHA256 = b"\x13\x01"

CHANGE_CIPHER = b"\x14"
ALERT = b"\x15"
HANDSHAKE = b"\x16"
APPLICATION_DATA = b"\x17"


class HandshakeType(IntEnum):
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    HELLO_RETRY_REQUEST = 6
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    CERTIFICATE_URL = 21
    CERTIFICATE_STATUS = 22
    SUPPLEMENTAL_DATA = 23
    KEY_UPDATE = 24
    MESSAGE_HASH = 254


class ExtensionType(IntEnum):
    SERVER_NAME = 0                             # RFC 6066
    MAX_FRAGMENT_LENGTH = 1                     # RFC 6066
    STATUS_REQUEST = 5                          # RFC 6066
    SUPPORTED_GROUPS = 10                       # RFC 8422, 7919
    SIGNATURE_ALGORITHMS = 13                   # RFC 8446
    USE_SRTP = 14                               # RFC 5764
    HEARTBEAT = 15                              # RFC 6520
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16 # RFC 7301
    SIGNED_CERTIFICATE_TIMESTAMP = 18           # RFC 6962
    CLIENT_CERTIFICATE_TYPE = 19                # RFC 7250
    SERVER_CERTIFICATE_TYPE = 20                # RFC 7250
    PADDING = 21                                # RFC 7685
    PRE_SHARED_KEY = 41                         # RFC 8446
    EARLY_DATA = 42                             # RFC 8446
    SUPPORTED_VERSIONS = 43                     # RFC 8446
    COOKIE = 44                                 # RFC 8446
    PSK_KEY_EXCHANGE_MODES = 45                 # RFC 8446
    CERTIFICATE_AUTHORITIES = 47                # RFC 8446
    OID_FILTERS = 48                            # RFC 8446
    POST_HANDSHAKE_AUTH = 49                    # RFC 8446
    SIGNATURE_ALGORITHMS_CERT = 50              # RFC 8446
    KEY_SHARE = 51                              # RFC 8446


class SignatureScheme(IntEnum):
    # RSASSA-PKCS1-v1_5 algorithms
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601

    # ECDSA algorithms
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503
    ECDSA_SECP521R1_SHA512 = 0x0603

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    RSA_PSS_RSAE_SHA256 = 0x0804
    RSA_PSS_RSAE_SHA384 = 0x0805
    RSA_PSS_RSAE_SHA512 = 0x0806

    # EdDSA algorithms
    ED25519 = 0x0807
    ED448 = 0x0808

    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    RSA_PSS_PSS_SHA256 = 0x0809
    RSA_PSS_PSS_SHA384 = 0x080A
    RSA_PSS_PSS_SHA512 = 0x080B

    # Legacy algorithms
    RSA_PKCS1_SHA1 = 0x0201
    ECDSA_SHA1 = 0x0203


class CertificateType(IntEnum):
    X509 = 0
    RAW_PUBLIC_KEY = 2


# BYTE MANIPULATION HELPERS
def bytes_to_num(b):
    return int.from_bytes(b, "big")


def num_to_bytes(num, bytes_len):
    return int.to_bytes(num, bytes_len, "big")


def rotr(num, count):
    return num >> count | num << (32 - count)


def xor(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


def mutliply_blocks(x, y):
    z = 0
    for i in range(128):
        if x & (1 << (127 - i)):
            z ^= y
        y = (y >> 1) ^ (0xE1 << 120) if y & 1 else y >> 1
    return z


def ghash(h, data):
    CHUNK_LEN = 16

    y = 0
    for pos in range(0, len(data), CHUNK_LEN):
        chunk = bytes_to_num(data[pos : pos + CHUNK_LEN])
        y = mutliply_blocks(y ^ chunk, h)
    return y


# SYMMETRIC CIPHERS
AES_ROUNDS = 10

# AES_SBOX is some permutation of numbers 0-255
AES_SBOX = [
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125,
    250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204,
    52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235,
    39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209,
    0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51,
    133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33,
    16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96,
    129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36,
    92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244,
    234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139,
    138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17,
    105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104,
    65, 153, 45, 15, 176, 84, 187, 22
]


def aes128_expand_key(key):
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    enc_keys = [[0, 0, 0, 0] for i in range(AES_ROUNDS + 1)]
    enc_keys[0] = [bytes_to_num(key[i:i + 4]) for i in [0, 4, 8, 12]]

    for t in range(1, AES_ROUNDS + 1):
        prev_key = enc_keys[t-1]
        enc_keys[t][0] = ((AES_SBOX[(prev_key[3] >> 8*2) & 0xFF] << 8*3) ^
                        (AES_SBOX[(prev_key[3] >> 8*1) & 0xFF] << 8*2) ^
                        (AES_SBOX[(prev_key[3] >> 8*0) & 0xFF] << 8*1) ^
                        (AES_SBOX[(prev_key[3] >> 8*3) & 0xFF] << 8*0) ^
                        (RCON[t-1] << 8*3) ^ prev_key[0])

        for i in range(1, 4):
            enc_keys[t][i] = enc_keys[t][i-1] ^ prev_key[i]
    return enc_keys


def aes128_encrypt(key, plaintext):
    TWOTIMES = [2*num if 2*num < 256 else 2*num & 0xff ^ 27 for num in range(256)]

    enc_keys = aes128_expand_key(key)

    t = [bytes_to_num(plaintext[4*i:4*i + 4]) ^ enc_keys[0][i] for i in range(4)]
    for r in range(1, AES_ROUNDS):
        t = [[AES_SBOX[(t[(i + 0) % 4] >> 8*3) & 0xFF],
            AES_SBOX[(t[(i + 1) % 4] >> 8*2) & 0xFF],
            AES_SBOX[(t[(i + 2) % 4] >> 8*1) & 0xFF],
            AES_SBOX[(t[(i + 3) % 4] >> 8*0) & 0xFF]] for i in range(4)]

        t = [[c[1] ^ c[2] ^ c[3] ^ TWOTIMES[c[0] ^ c[1]],
            c[0] ^ c[2] ^ c[3] ^ TWOTIMES[c[1] ^ c[2]],
            c[0] ^ c[1] ^ c[3] ^ TWOTIMES[c[2] ^ c[3]],
            c[0] ^ c[1] ^ c[2] ^ TWOTIMES[c[3] ^ c[0]]] for c in t]

        t = [bytes_to_num(t[i]) ^ enc_keys[r][i] for i in range(4)]

    result = [bytes([
        AES_SBOX[(t[(i + 0) % 4] >> 8*3) & 0xFF] ^ (enc_keys[-1][i] >> 8*3) & 0xFF,
        AES_SBOX[(t[(i + 1) % 4] >> 8*2) & 0xFF] ^ (enc_keys[-1][i] >> 8*2) & 0xFF,
        AES_SBOX[(t[(i + 2) % 4] >> 8*1) & 0xFF] ^ (enc_keys[-1][i] >> 8*1) & 0xFF,
        AES_SBOX[(t[(i + 3) % 4] >> 8*0) & 0xFF] ^ (enc_keys[-1][i] >> 8*0) & 0xFF
    ]) for i in range(4)]
    return b"".join(result)


def aes128_ctr_encrypt(key, msg, nonce, counter_start_val):
    BLOCK_SIZE = 16

    ans = []
    counter = counter_start_val
    for s in range(0, len(msg), BLOCK_SIZE):
        chunk = msg[s : s + BLOCK_SIZE]

        chunk_nonce = nonce + num_to_bytes(counter, 4)
        encrypted_chunk_nonce = aes128_encrypt(key, chunk_nonce)

        decrypted_chunk = xor(chunk, encrypted_chunk_nonce)
        ans.append(decrypted_chunk)

        counter += 1
    return b"".join(ans)


def aes128_ctr_decrypt(key, msg, nonce, counter_start_val):
    return aes128_ctr_encrypt(key, msg, nonce, counter_start_val)


def calc_pretag(key, encrypted_msg, associated_data):
    v = b"\x00" * (16 * ((len(associated_data) + 15) // 16) - len(associated_data))
    u = b"\x00" * (16 * ((len(encrypted_msg) + 15) // 16) - len(encrypted_msg))

    h = bytes_to_num(aes128_encrypt(key, b"\x00" * 16))
    data = (
        associated_data
        + v
        + encrypted_msg
        + u
        + num_to_bytes(len(associated_data) * 8, 8)
        + num_to_bytes(len(encrypted_msg) * 8, 8)
    )
    return num_to_bytes(ghash(h, data), 16)


def aes128_gcm_decrypt(key, msg, nonce, associated_data):
    TAG_LEN = 16

    encrypted_msg, tag = msg[:-TAG_LEN], msg[-TAG_LEN:]

    pretag = calc_pretag(key, encrypted_msg, associated_data)
    check_tag = aes128_ctr_encrypt(key, pretag, nonce, counter_start_val=1)
    if check_tag != tag:
        raise ValueError("Decrypt error, bad tag")
    return aes128_ctr_decrypt(key, encrypted_msg, nonce, counter_start_val=2)


def aes128_gcm_encrypt(key, msg, nonce, associated_data):
    encrypted_msg = aes128_ctr_encrypt(key, msg, nonce, counter_start_val=2)

    pretag = calc_pretag(key, encrypted_msg, associated_data)
    tag = aes128_ctr_encrypt(key, pretag, nonce, counter_start_val=1)
    return encrypted_msg + tag


def one_shot_sha256(data):
    m = sha256()
    m.update(data)
    return m.digest()


def hmac_sha256(key, data):
    BLOCK_SIZE = 512 // 8
    IPAD = b"\x36" * BLOCK_SIZE
    OPAD = b"\x5c" * BLOCK_SIZE

    if len(key) <= BLOCK_SIZE:
        key += b"\x00" * (BLOCK_SIZE - len(key))
    else:
        key = one_shot_sha256(key)
    return one_shot_sha256(xor(key, OPAD) + one_shot_sha256(xor(key, IPAD) + data))


def derive_secret(label, key, data, hash_len):
    full_label = b"tls13 " + label
    packed_data = (
        num_to_bytes(hash_len, 2)
        + num_to_bytes(len(full_label), 1)
        + full_label
        + num_to_bytes(len(data), 1)
        + data
    )

    secret = bytearray()
    i = 1
    while len(secret) < hash_len:
        secret += hmac_sha256(key, secret[-32:] + packed_data + num_to_bytes(i, 1))
        i += 1
    return bytes(secret[:hash_len])


# ELLIPTIC CURVE FUNCTIONS
def egcd(a, b):
    if a == 0:
        return 0, 1
    y, x = egcd(b % a, a)
    return x - (b // a) * y, y


def mod_inv(a, p):
    return egcd(a, p)[0] if a >= 0 else p - egcd(-a, p)[0]


def add_two_ec_points(p1_x, p1_y, p2_x, p2_y, a, p):
    if p1_x == p2_x and p1_y == p2_y:
        s = (3 * p1_x * p1_x + a) * mod_inv(2 * p2_y, p)
    elif p1_x != p2_x:
        s = (p1_y - p2_y) * mod_inv(p1_x - p2_x, p)
    else:
        raise NotImplementedError

    x = s * s - p1_x - p2_x
    y = -p1_y + s * (p1_x - x)
    return x % p, y % p


def multiply_num_on_ec_point(num, g_x, g_y, a, p):
    x, y = None, None
    while num:
        if num & 1:
            x, y = add_two_ec_points(x, y, g_x, g_y, a, p) if x else (g_x, g_y)
        g_x, g_y = add_two_ec_points(g_x, g_y, g_x, g_y, a, p)
        num >>= 1
    return x, y


# AUTHENTIATED ENCRYPTION HELPERS
def do_authenticated_encryption(key, nonce_base, seq_num, msg_type, payload):
    TAG_LEN = 16

    payload += msg_type
    nonce = xor(nonce_base, num_to_bytes(seq_num, 12))
    data = APPLICATION_DATA + LEGACY_TLS_VERSION + num_to_bytes(len(payload) + TAG_LEN, 2)

    encrypted_msg = aes128_gcm_encrypt(key, payload, nonce, associated_data=data)
    return encrypted_msg


def do_authenticated_decryption(key, nonce_start, seq_num, msg_type, payload):
    nonce = xor(nonce_start, num_to_bytes(seq_num, 12))

    data = msg_type + LEGACY_TLS_VERSION + num_to_bytes(len(payload), 2)
    msg = aes128_gcm_decrypt(key, payload, nonce, associated_data=data)

    msg_type, msg_data = msg[-1:], msg[:-1]
    return msg_type, msg_data


class Extension:
    def __init__(self, type, value) -> None:
        self.type = type
        self.value = value


class Parser:
    def __init__(self, buffer: bytes, offset=0) -> None:
        self.buffer = buffer
        self.offset = offset

    def get_uint8(self):
        v = self.buffer[self.offset]
        self.offset += 1
        return v

    def get_uint16(self):
        v = bytes_to_num(self.buffer[self.offset : self.offset + 2])
        self.offset += 2
        return v

    def get_uint24(self):
        v = bytes_to_num(self.buffer[self.offset : self.offset + 3])
        self.offset += 3
        return v

    def get_data(self, len):
        v = self.buffer[self.offset : self.offset + len]
        self.offset += len
        return v

    def bytes_left(self):
        return len(self.buffer) - self.offset


class ManualComm(ABC):
    @abstractmethod
    def prepare_send(self, data) -> None:
        pass

    @abstractmethod
    def sendall(self, data) -> None:
        pass

    @abstractmethod
    def recv(self, bufsize: int) -> bytes:
        pass


class ManualTls:
    def __init__(self) -> None:
        pass

    def initialize(self, comm: ManualComm, cert_type: CertificateType):
        self.comm = comm
        self.server_certificate_type = 0
        self.client_certificate_type = 0
        self.signature_algorithms = []
        self.client_certificate_requested = False
        self.cert_type = cert_type

    # NETWORK AND LOW LEVEL TLS PROTOCOL HELPERS
    def recv_num_bytes(self, num):
        ret = bytearray()
        while len(ret) < num:
            data = self.comm.recv(min(4096, num - len(ret)))
            if not data:
                raise BrokenPipeError
            ret += data
        return bytes(ret)

    def recv_tls(self):
        rec_type = self.recv_num_bytes(1)
        # tls_version = self.recv_num_bytes(s, 2)
        _ = self.recv_num_bytes(2)

        # "The value of TLSPlaintext.legacy_record_version MUST be ignored by all implementations.""
        # assert tls_version == LEGACY_TLS_VERSION

        rec_len = bytes_to_num(self.recv_num_bytes(2))
        rec = self.recv_num_bytes(rec_len)
        return rec_type, rec

    def prepare_send_tls(self, rec_type, msg):
        tls_record = rec_type + LEGACY_TLS_VERSION + num_to_bytes(len(msg), 2) + msg
        self.comm.prepare_send(tls_record)

    def send_tls(self, rec_type, msg):
        tls_record = rec_type + LEGACY_TLS_VERSION + num_to_bytes(len(msg), 2) + msg
        self.comm.sendall(tls_record)

    def recv_tls_and_decrypt(self, key, nonce, seq_num):
        rec_type, encrypted_msg = self.recv_tls()
        assert rec_type == APPLICATION_DATA

        msg_type, msg = do_authenticated_decryption(key, nonce, seq_num, APPLICATION_DATA, encrypted_msg)
        logger.debug(f"Received handshake type: {msg[0]} ({HandshakeType(msg[0]).name})")
        return msg_type, msg

    def parse_extension(self, buff, offset):
        type = bytes_to_num(buff[offset : offset + 2])
        len = bytes_to_num(buff[offset + 2 : offset + 4])
        value = buff[offset + 4 : offset + 4 + len]

        return type, len, value

    # PACKET GENERATORS AND HANDLERS
    def gen_client_hello(self, client_random, ecdh_pubkey_x, ecdh_pubkey_y):
        CLIENT_HELLO = b"\x01"

        session_id = b""
        compression_method = b"\x00"  # no compression

        supported_versions = b"\x00\x2b"
        supported_versions_length = b"\x00\x03"
        another_supported_versions_length = b"\x02"
        tls1_3_version = b"\x03\x04"
        supported_version_extension = (
            supported_versions
            + supported_versions_length
            + another_supported_versions_length
            + tls1_3_version
        )

        signature_algos = b"\x00\x0d"
        signature_algos_length = b"\x00\x04"
        another_signature_algos_length = b"\x00\x02"
        rsa_pss_rsae_sha256_algo = b"\x08\x04"
        signature_algos_extension = (
            signature_algos
            + signature_algos_length
            + another_signature_algos_length
            + rsa_pss_rsae_sha256_algo
        )

        supported_groups = b"\x00\x0a"
        supported_groups_length = b"\x00\x04"
        another_supported_groups_length = b"\x00\x02"
        secp256r1_group = b"\x00\x17"
        supported_groups_extension = (
            supported_groups
            + supported_groups_length
            + another_supported_groups_length
            + secp256r1_group
        )

        ecdh_pubkey = b"\x04" + num_to_bytes(ecdh_pubkey_x, 32) + num_to_bytes(ecdh_pubkey_y, 32)

        key_share = b"\x00\x33"
        key_share_length = num_to_bytes(len(ecdh_pubkey) + 4 + 2, 2)
        another_key_share_length = num_to_bytes(len(ecdh_pubkey) + 4, 2)
        key_exchange_len = num_to_bytes(len(ecdh_pubkey), 2)
        key_share_extension = (
            key_share
            + key_share_length
            + another_key_share_length
            + secp256r1_group
            + key_exchange_len
            + ecdh_pubkey
        )

        extensions = (
            supported_version_extension
            + signature_algos_extension
            + supported_groups_extension
            + key_share_extension
        )

        client_hello_data = (
            LEGACY_TLS_VERSION
            + client_random
            + num_to_bytes(len(session_id), 1)
            + session_id
            + num_to_bytes(len(TLS_AES_128_GCM_SHA256), 2)
            + TLS_AES_128_GCM_SHA256
            + num_to_bytes(len(compression_method), 1)
            + compression_method
            + num_to_bytes(len(extensions), 2)
        ) + extensions

        client_hello_len_bytes = num_to_bytes(len(client_hello_data), 3)
        client_hello_tlv = CLIENT_HELLO + client_hello_len_bytes + client_hello_data

        logger.debug(f"    Type is the client hello: {CLIENT_HELLO.hex()}")
        logger.debug(f"    Length is {len(client_hello_data)}: {client_hello_len_bytes.hex()}")
        logger.debug(f"    Legacy client version is TLS 1.2: {LEGACY_TLS_VERSION.hex()}")
        logger.debug(f"    Client random: {client_random.hex()}")
        logger.debug(f"    Session id len is 0: {num_to_bytes(len(session_id), 1).hex()}")
        logger.debug(f"    Session id: {session_id.hex()}")
        logger.debug(f"    Cipher suites len is 2: {num_to_bytes(len(TLS_AES_128_GCM_SHA256), 2)}")
        logger.debug(f"    Cipher suite is TLS_AES_128_GCM_SHA256: {TLS_AES_128_GCM_SHA256.hex()}")
        logger.debug(f"    Compression method len is 1: {num_to_bytes(len(compression_method), 1).hex()}")
        logger.debug(f"    Compression method is no compression: {compression_method.hex()}")
        logger.debug(f"    Extensions len is {len(extensions)}: {num_to_bytes(len(extensions), 2).hex()}")
        logger.debug(f"    Extension type is supported_versions: {supported_versions.hex()}")
        logger.debug(f"        Extension len is 3: {supported_versions_length.hex()}")
        logger.debug(f"        Extension field len is 2: {another_supported_versions_length.hex()}")
        logger.debug(f"        Version is TLS 1.3: {tls1_3_version.hex()}")
        logger.debug(f"    Extension type is signature_algos: {signature_algos.hex()}")
        logger.debug(f"        Extension len is 4: {signature_algos_length.hex()}")
        logger.debug(f"        Extension field len is 2: {another_signature_algos_length.hex()}")
        logger.debug(f"        Algo is rsa_pss_rsae_sha256_algo: {rsa_pss_rsae_sha256_algo.hex()}")
        logger.debug(f"    Extension type is supported_groups: {supported_groups.hex()}")
        logger.debug(f"        Extension len is 4: {supported_groups_length.hex()}")
        logger.debug(f"        Extension field len is 2: {another_supported_groups_length.hex()}")
        logger.debug(f"        Group is secp256r1_group: {secp256r1_group.hex()}")
        logger.debug(f"    Extension type is key_share: {key_share.hex()}")
        logger.debug(f"        Extension len is {bytes_to_num(key_share_length)}: {key_share_length.hex()}")
        logger.debug(f"        Extension field len is {bytes_to_num(another_key_share_length)}: {another_key_share_length.hex()}")
        logger.debug(f"        Key length {len(ecdh_pubkey)}: {key_exchange_len.hex()}")
        logger.debug(f"        Key is: {ecdh_pubkey.hex()}")

        return client_hello_tlv

    def handle_server_hello(self, server_hello):
        handshake_type = server_hello[0]

        SERVER_HELLO = 0x2
        assert handshake_type == SERVER_HELLO

        server_hello_len = server_hello[1:4]
        server_version = server_hello[4:6]

        server_random = server_hello[6:38]

        session_id_len = bytes_to_num(server_hello[38:39])
        session_id = server_hello[39 : 39 + session_id_len]

        cipher_suite = server_hello[39 + session_id_len : 39 + session_id_len + 2]
        assert cipher_suite == TLS_AES_128_GCM_SHA256

        compression_method = server_hello[39 + session_id_len + 2 : 39 + session_id_len + 3]

        extensions_length = bytes_to_num(server_hello[39 + session_id_len + 3 : 39 + session_id_len + 3 + 2])
        extensions = server_hello[
            39
            + session_id_len
            + 3
            + 2 : 39
            + session_id_len
            + 3
            + 2
            + extensions_length
        ]

        public_ec_key = b""
        ptr = 0
        while ptr < extensions_length:
            extension_type = extensions[ptr : ptr + 2]
            extension_length = bytes_to_num(extensions[ptr + 2 : ptr + 4])
            KEY_SHARE = b"\x00\x33"
            if extension_type != KEY_SHARE:
                ptr += extension_length + 4
                continue
            group = extensions[ptr + 4 : ptr + 6]
            SECP256R1_GROUP = b"\x00\x17"
            assert group == SECP256R1_GROUP
            key_exchange_len = bytes_to_num(extensions[ptr + 6 : ptr + 8])

            public_ec_key = extensions[ptr + 8 : ptr + 8 + key_exchange_len]
            break

        if not public_ec_key:
            raise ValueError("No public ECDH key in server hello")

        public_ec_key_x = bytes_to_num(public_ec_key[1:33])
        public_ec_key_y = bytes_to_num(public_ec_key[33:])

        logger.debug(f"    Type is the server hello: {server_hello[:1].hex()}")
        logger.debug(f"    Length is {bytes_to_num(server_hello_len)}: {server_hello_len.hex()}")
        logger.debug(f"    Legacy server version is TLS 1.2: {server_version.hex()}")
        logger.debug(f"    Server random: {server_random.hex()}")
        logger.debug(f"    Session id len is {session_id_len}: {server_hello[38:39].hex()}")
        logger.debug(f"    Session id: {session_id.hex()}")
        logger.debug(f"    Cipher suite is TLS_AES_128_GCM_SHA256: {cipher_suite.hex()}")
        logger.debug(f"    Compression method is no compression: {compression_method.hex()}")
        logger.debug(f"    Extensions len is {extensions_length}: {num_to_bytes(extensions_length, 2).hex()}")
        logger.debug(f"    Extension parsing was skipped, but public_ec_key is {public_ec_key.hex()}")

        return server_random, session_id, public_ec_key_x, public_ec_key_y

    def handle_encrypted_extensions(self, msg):
        assert msg[0] == HandshakeType.ENCRYPTED_EXTENSIONS
        extensions_length = bytes_to_num(msg[1:4])
        assert len(msg[4:]) >= extensions_length

        offset = 4
        extensions_length = bytes_to_num(msg[offset : offset + 2])
        offset += 2
        while extensions_length > 0:
            type, length, value = self.parse_extension(msg, offset)
            offset += length + 4
            extensions_length -= length + 4

            logger.debug(f"        Encrypted_Extension: {ExtensionType(type).name} - {value.hex()}")

            if type == ExtensionType.SERVER_CERTIFICATE_TYPE:
                self.server_certificate_type = value[0]
            elif type == ExtensionType.CLIENT_CERTIFICATE_TYPE:
                self.client_certificate_type = value[0]

    def handle_cert_request(self, cert_request_data):
        offset = 0
        handshake_type = cert_request_data[offset]
        offset += 1

        assert handshake_type == HandshakeType.CERTIFICATE_REQUEST

        extensions_length = bytes_to_num(cert_request_data[1:4])
        offset += 3
        assert len(cert_request_data[4:]) >= extensions_length

        self.client_certificate_ctx = b""
        context_len = cert_request_data[offset]
        offset += 1
        if context_len > 0:
            self.client_certificate_ctx = cert_request_data[offset : offset + context_len]
            offset += context_len

        extensions_length = bytes_to_num(cert_request_data[offset : offset + 2])
        offset += 2
        while extensions_length > 0:
            type, length, value = self.parse_extension(cert_request_data, offset)
            offset += length + 4
            extensions_length -= length + 4

            logger.debug(f"        Cert_request_extension: {ExtensionType(type).name} - {value.hex()}")

            if type == ExtensionType.SIGNATURE_ALGORITHMS:
                sig_scheme_length = bytes_to_num(value[:2])
                pos = 0
                while pos < sig_scheme_length:
                    alg = bytes_to_num(value[2 + pos : 2 + pos + 2])
                    pos += 2
                    self.signature_algorithms.append(alg)

        for alg in self.signature_algorithms:
            logger.debug(f"            Signature_alg: {hex(alg)} ({SignatureScheme(alg).name})")

        self.client_certificate_requested = True

    def handle_server_cert(self, server_cert_data):
        p = Parser(server_cert_data)

        handshake_type = p.get_uint8()
        assert handshake_type == HandshakeType.CERTIFICATE

        certificate_field_len = p.get_uint24()
        assert certificate_field_len == p.bytes_left()

        certificates = []

        cert_request_context_length = p.get_uint8()
        if cert_request_context_length > 0:
            # not used now
            _ = p.get_data(cert_request_context_length)

        certificate_field_len = p.get_uint24()

        while p.bytes_left() > 0:
            cert_len = p.get_uint24()
            cert = p.get_data(cert_len)
            logger.debug(f"cert: {cert.hex()}")
            certificates.append(cert)

            # skip extensions
            ext_len = p.get_uint16()
            if ext_len > 0:
                _ = p.get_data(ext_len)

        return certificates

    def handle_cert_verify(self, cert_verify_data, rsa, msgs_so_far):
        p = Parser(cert_verify_data)

        handshake_type = p.get_uint8()
        assert handshake_type == HandshakeType.CERTIFICATE_VERIFY

        cert_verify_len = p.get_uint24()
        assert cert_verify_len == p.bytes_left()

        algorithm = p.get_uint16()
        logger.debug(f"        algorithm: {hex(algorithm)} ({SignatureScheme(algorithm).name})")
        signature_len = p.get_uint16()
        signature = p.get_data(signature_len)
        logger.debug(f"        signature: {signature.hex()}")
        logger.debug(f"        msgs_so_far: {msgs_so_far.hex()}")

        tbs = (
            b" " * 64
            + b"TLS 1.3, server CertificateVerify"
            + b"\x00"
            + one_shot_sha256(msgs_so_far)
        )

        if algorithm == SignatureScheme.ECDSA_SECP256R1_SHA256:
            pub_key = VerifyingKey.from_der(self.server_certs[0])
            valid = pub_key.verify(signature, tbs, sha256, sigdecode=sigdecode_der)
            return valid
        else:
            # not implemented
            return True

    def handle_finished(self, finished_data, server_finished_key, msgs_so_far):
        handshake_type = finished_data[0]

        assert handshake_type == HandshakeType.FINISHED

        verify_data_len = bytes_to_num(finished_data[1:4])
        verify_data = finished_data[4 : 4 + verify_data_len]

        hmac_digest = hmac_sha256(server_finished_key, one_shot_sha256(msgs_so_far))
        return verify_data == hmac_digest

    def gen_change_cipher(self):
        CHANGE_CIPHER_SPEC_MSG = b"\x01"
        return CHANGE_CIPHER_SPEC_MSG

    def gen_encrypted_finished(self, client_write_key, client_write_iv, client_seq_num, client_finish_val):
        FINISHED = b"\x14"
        msg = FINISHED + num_to_bytes(len(client_finish_val), 3) + client_finish_val

        return do_authenticated_encryption(client_write_key, client_write_iv, client_seq_num, HANDSHAKE, msg)

    def gen_encrypted_client_certificate(
        self, client_write_key, client_write_iv, client_seq_num
    ):

        spk = VerifyingKey.to_der(self.client_key.verifying_key)
        certificate_entry = num_to_bytes(len(spk), 3) + spk + bytes(b"\x00\x00")
        certificate = (
            bytes(b"\x00") + num_to_bytes(len(certificate_entry), 3) + certificate_entry
        )

        msg = (
            bytes([HandshakeType.CERTIFICATE])
            + num_to_bytes(len(certificate), 3)
            + certificate
        )

        return (
            do_authenticated_encryption(
                client_write_key, client_write_iv, client_seq_num, HANDSHAKE, msg
            ),
            msg,
        )

    def gen_encrypted_client_certificate_verify(
        self, client_write_key, client_write_iv, client_seq_num, msgs_so_far
    ):

        digest = one_shot_sha256(msgs_so_far)
        logger.debug(f"digest: {digest.hex()}")

        tbs = b" " * 64 + b"TLS 1.3, client CertificateVerify" + b"\x00" + digest

        signature = self.client_key.sign(tbs, hashfunc=sha256, sigencode=sigencode_der)
        certificate_verify = (
            num_to_bytes(SignatureScheme.ECDSA_SECP256R1_SHA256, 2)
            + num_to_bytes(len(signature), 2)
            + signature
        )

        msg = (
            bytes([HandshakeType.CERTIFICATE_VERIFY])
            + num_to_bytes(len(certificate_verify), 3)
            + certificate_verify
        )

        return (
            do_authenticated_encryption(
                client_write_key, client_write_iv, client_seq_num, HANDSHAKE, msg
            ),
            msg,
        )

    def generate_client_key(self):
        self.client_key = SigningKey.generate(curve=NIST256p)
        pub_key = self.client_key.verifying_key.to_string()
        return pub_key[0:32], pub_key[32:64]

    def load_client_key(self, key_file):
        with open(key_file, "r") as file:
            pem = file.read()
            self.client_key = SigningKey.from_pem(pem)
            pub_key = self.client_key.verifying_key.to_string()
            return pub_key[0:32], pub_key[32:64]

    def load_client_certificate(self, cert_file):
        with open(cert_file, "r") as file:
            pem = file.read()
            cert = x509.load_pem_x509_certificate(bytes(pem, "ASCII"), default_backend())
            self.client_cert = cert.public_bytes(serialization.Encoding.DER)

    def is_client_certificate_requested(self) -> bool:
        return self.client_certificate_requested

    def establish(self):
        logger.debug("Generating params for a client hello, the first message of TLS handshake")
        SECP256R1_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        SECP256R1_A = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
        SECP256R1_G = (
            0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
        )

        client_random = b"\xAB" * 32
        our_ecdh_privkey = 42
        our_ecdh_pubkey_x, our_ecdh_pubkey_y = multiply_num_on_ec_point(
            our_ecdh_privkey, SECP256R1_G[0], SECP256R1_G[1], SECP256R1_A, SECP256R1_P
        )

        logger.debug(f"    Client random: {client_random.hex()}")
        logger.debug(f"    Our ECDH (Elliptic-curve Diffie-Hellman) private key: {our_ecdh_privkey}")
        logger.debug(f"    Our ECDH public key: x={our_ecdh_pubkey_x} y={our_ecdh_pubkey_y}")

        logger.debug("Generating the client hello")
        client_hello = self.gen_client_hello(client_random, our_ecdh_pubkey_x, our_ecdh_pubkey_y)

        logger.debug("Sending the client hello")
        self.send_tls(HANDSHAKE, client_hello)

        ###########################
        logger.debug("Receiving a server hello")
        rec_type, server_hello = self.recv_tls()

        if rec_type == ALERT:
            logger.error("Server sent us ALERT, it probably doesn't support TLS_AES_128_GCM_SHA256 algo")
            exit(1)

        assert rec_type == HANDSHAKE

        server_random, session_id, server_ecdh_pubkey_x, server_ecdh_pubkey_y = self.handle_server_hello(server_hello)
        logger.debug(f"    Server ECDH public key: x={server_ecdh_pubkey_x} y={server_ecdh_pubkey_y}")

        ###########################
        logger.debug("Receiving a change cipher msg, all communication will be encrypted")
        rec_type, server_change_cipher = self.recv_tls()
        assert rec_type == CHANGE_CIPHER

        self.server_ecdh_pubkey_x = server_ecdh_pubkey_x
        self.server_ecdh_pubkey_y = server_ecdh_pubkey_y

        our_secret_point_x = multiply_num_on_ec_point(
            our_ecdh_privkey,
            server_ecdh_pubkey_x,
            server_ecdh_pubkey_y,
            SECP256R1_A,
            SECP256R1_P,
        )[0]
        our_secret = num_to_bytes(our_secret_point_x, 32)
        logger.debug(f"    Our common ECDH secret is: {our_secret.hex()}, deriving keys")

        early_secret = hmac_sha256(key=b"", data=b"\x00" * 32)
        preextractsec = derive_secret(b"derived", key=early_secret, data=one_shot_sha256(b""), hash_len=32)
        handshake_secret = hmac_sha256(key=preextractsec, data=our_secret)
        hello_hash = one_shot_sha256(client_hello + server_hello)
        server_hs_secret = derive_secret(b"s hs traffic", key=handshake_secret, data=hello_hash, hash_len=32)
        server_write_key = derive_secret(b"key", key=server_hs_secret, data=b"", hash_len=16)
        server_write_iv = derive_secret(b"iv", key=server_hs_secret, data=b"", hash_len=12)
        server_finished_key = derive_secret(b"finished", key=server_hs_secret, data=b"", hash_len=32)
        client_hs_secret = derive_secret(b"c hs traffic", key=handshake_secret, data=hello_hash, hash_len=32)
        client_write_key = derive_secret(b"key", key=client_hs_secret, data=b"", hash_len=16)
        client_write_iv = derive_secret(b"iv", key=client_hs_secret, data=b"", hash_len=12)
        client_finished_key = derive_secret(b"finished", key=client_hs_secret, data=b"", hash_len=32)

        logger.debug(f"    server_write_key {server_write_key.hex()} server_write_iv {server_write_iv.hex()}")
        logger.debug(f"    server_finished_key {server_finished_key.hex()}")
        logger.debug(f"    client_write_key {client_write_key.hex()} client_write_iv {client_write_iv.hex()}")
        logger.debug(f"    client_finished_key {client_finished_key.hex()}")

        client_seq_num = 0  # for use in authenticated encryption
        server_seq_num = 0

        ###########################
        logger.debug("Receiving encrypted extensions")
        rec_type, encrypted_extensions = self.recv_tls_and_decrypt(server_write_key, server_write_iv, server_seq_num)
        assert rec_type == HANDSHAKE
        server_seq_num += 1

        logger.debug(f"    Encrypted_extensions: {encrypted_extensions.hex()}")
        self.handle_encrypted_extensions(encrypted_extensions)

        msgs_so_far = client_hello + server_hello + encrypted_extensions

        ###########################
        logger.debug("Receiving server certificates")
        rec_type, server_cert = self.recv_tls_and_decrypt(server_write_key, server_write_iv, server_seq_num)
        assert rec_type == HANDSHAKE
        server_seq_num += 1

        if server_cert[0] == HandshakeType.CERTIFICATE_REQUEST:
            logger.debug(f"    Certificate_request: {server_cert.hex()}")

            self.handle_cert_request(server_cert)

            msgs_so_far = msgs_so_far + server_cert

            rec_type, server_cert = self.recv_tls_and_decrypt(server_write_key, server_write_iv, server_seq_num)
            assert rec_type == HANDSHAKE
            server_seq_num += 1

        logger.debug(f"    Certificate: {server_cert.hex()}")

        self.server_certs = self.handle_server_cert(server_cert)
        logger.debug(f"    Got {len(self.server_certs)} certs")

        msgs_so_far = msgs_so_far + server_cert

        ###########################
        logger.debug("Receiving server verify certificate")
        rec_type, cert_verify = self.recv_tls_and_decrypt(server_write_key, server_write_iv, server_seq_num)
        assert rec_type == HANDSHAKE
        server_seq_num += 1

        logger.debug(f"    Certificate_verify: {cert_verify.hex()}")

        cert_ok = self.handle_cert_verify(cert_verify, None, msgs_so_far)
        logger.debug(f"    Certificate verifying ststus: {cert_ok}")
        if not cert_ok:
            raise Exception("Unable to verify server certificate!")

        ###########################
        logger.debug("Receiving server finished")
        rec_type, finished = self.recv_tls_and_decrypt(server_write_key, server_write_iv, server_seq_num)
        assert rec_type == HANDSHAKE
        server_seq_num += 1

        msgs_so_far = msgs_so_far + cert_verify
        srv_finish_ok = self.handle_finished(finished, server_finished_key, msgs_so_far)
        if srv_finish_ok:
            logger.debug("    Server sent valid finish handshake msg")
        else:
            logger.warning("    Warning: Server sent wrong handshake finished msg")

        ###########################
        logger.debug("Handshake: sending a change cipher msg")
        self.prepare_send_tls(CHANGE_CIPHER, self.gen_change_cipher())

        ###########################
        # All client messages beyond this point are encrypted
        msgs_so_far = msgs_so_far + finished
        transcript_hash = one_shot_sha256(msgs_so_far)

        if self.is_client_certificate_requested():
            client_certificate_msg, msg = self.gen_encrypted_client_certificate(
                client_write_key, client_write_iv, client_seq_num
            )

            if client_certificate_msg is not None:
                self.prepare_send_tls(APPLICATION_DATA, client_certificate_msg)
                client_seq_num += 1
                msgs_so_far = msgs_so_far + msg

            client_certificate_verify_msg, msg = (
                self.gen_encrypted_client_certificate_verify(
                    client_write_key, client_write_iv, client_seq_num, msgs_so_far
                )
            )

            if client_certificate_verify_msg is not None:
                self.prepare_send_tls(APPLICATION_DATA, client_certificate_verify_msg)
                client_seq_num += 1
                msgs_so_far = msgs_so_far + msg

        msgs_sha256 = one_shot_sha256(msgs_so_far)

        client_finish_val = hmac_sha256(client_finished_key, msgs_sha256)

        logger.debug("Handshake: sending an encrypted finished msg")
        encrypted_handshake_msg = self.gen_encrypted_finished(
            client_write_key, client_write_iv, client_seq_num, client_finish_val
        )
        logger.debug(f"    Client finish value {client_finish_val.hex()}")
        self.send_tls(APPLICATION_DATA, encrypted_handshake_msg)
        client_seq_num += 1

        logger.debug("Handshake finished, regenerating secrets for application data")

        ###########################
        # derive application secrets
        premaster_secret = derive_secret(b"derived", data=one_shot_sha256(b""), key=handshake_secret, hash_len=32)
        master_secret = hmac_sha256(key=premaster_secret, data=b"\x00" * 32)
        server_secret = derive_secret(b"s ap traffic", data=transcript_hash, key=master_secret, hash_len=32)
        self.server_write_key = derive_secret(b"key", data=b"", key=server_secret, hash_len=16)
        self.server_write_iv = derive_secret(b"iv", data=b"", key=server_secret, hash_len=12)
        client_secret = derive_secret(b"c ap traffic", data=transcript_hash, key=master_secret, hash_len=32)
        self.client_write_key = derive_secret(b"key", data=b"", key=client_secret, hash_len=16)
        self.client_write_iv = derive_secret(b"iv", data=b"", key=client_secret, hash_len=12)

        logger.debug(f"    server_write_key {self.server_write_key.hex()} server_write_iv {self.server_write_iv.hex()}")
        logger.debug(f"    client_write_key {self.client_write_key.hex()} client_write_iv {self.client_write_iv.hex()}")

        # reset sequence numbers
        self.client_seq_num = 0
        self.server_seq_num = 0

    def transmit(self, data=None):
        ###########################
        # the rest is just for fun
        logger.debug(f"Sending {data}")

        if data is not None:
            encrypted_msg = do_authenticated_encryption(
                self.client_write_key,
                self.client_write_iv,
                self.client_seq_num,
                APPLICATION_DATA,
                data,
            )
            self.send_tls(APPLICATION_DATA, encrypted_msg)
            self.client_seq_num += 1

        logger.debug("Receiving an answer")
        while True:
            try:
                rec_type, msg = self.recv_tls_and_decrypt(self.server_write_key, self.server_write_iv, self.server_seq_num)
                self.server_seq_num += 1
            except BrokenPipeError:
                logger.warning("Connection closed on TCP level")
                break

            if rec_type == APPLICATION_DATA:
                return msg
            elif rec_type == HANDSHAKE:
                NEW_SESSION_TICKET = 4
                if msg[0] == NEW_SESSION_TICKET:
                    logger.debug(f"New session ticket: {msg.hex()}")
            elif rec_type == ALERT:
                alert_level, alert_description = msg

                logger.warning(f"Got alert level: {alert_level}, description: {alert_description}")
                CLOSE_NOTIFY = 0
                if alert_description == CLOSE_NOTIFY:
                    logger.info("Server sent close_notify, no waiting for more data")
                    break
            else:
                logger.warning("Got msg with unknown rec_type", rec_type)
