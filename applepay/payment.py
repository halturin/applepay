from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import ciphers
from cryptography.hazmat.backends import default_backend


from binascii import hexlify, unhexlify
from base64 import b64decode
from hashlib import sha256


def applepaydecode(cert_pem , private_key_pem, ephemer_public_key, cipherdata64):
    private_key = load_pem_private_key(private_key_pem, None, default_backend())
    public_key = load_der_public_key(b64decode(ephemer_public_key), default_backend())
    cipherdata = b64decode(cipherdata64)
    shared_secred = private_key.exchange(ec.ECDH(), public_key)

    sha = sha256()
    sha.update(b'\0'*3)
    sha.update(b'\1')
    sha.update(shared_secred)
    sha.update(b'\x0did-aes256-GCM'+b'Apple'+unhexlify(extract_merc_id(cert_pem)))

    symmetric_key = sha.digest()

    mode = ciphers.modes.GCM(b'\0'*16, cipherdata[-16:], 16)
    decryptor = ciphers.Cipher(ciphers.algorithms.AES(symmetric_key), mode, backend=default_backend()).decryptor()

    return decryptor.update(cipherdata[:-16])+decryptor.finalize()

def extract_merc_id(cert_pem):
    return ''