from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.primitives import ciphers, hashes
from cryptography.hazmat.backends import default_backend


from binascii import hexlify, unhexlify
from base64 import b64decode
from hashlib import sha256

OID_MERCHANT_ID = "1.2.840.113635.100.6.32"
OID_LEAF_CERTIFICATE = "1.2.840.113635.100.6.29"
OID_INTERMEDIATE_CERTIFICATE = "1.2.840.113635.100.6.2.14"

ROOT_CA_FILE = 'ca/AppleRootCA-G3.cer'
AAI_CA_FILE = 'ca/AppleAAICAG3.cer'

class Payment:
    def __init__(self, merc_ca_pem, private_key_pem, root_ca_der = None, aai_ca_der = None):
        if root_ca_der == None:
            self._root_ca = load_der_x509_certificate(open(ROOT_CA_FILE, 'rb').read(), default_backend())
        else:
            self._root_ca = load_der_x509_certificate(root_ca_der)

        if aai_ca_der == None:
            self._aai_ca = load_der_x509_certificate(open(AAI_CA_FILE, 'rb').read(), default_backend())
        else:
            self._aai_ca = load_der_x509_certificate(aai_ca_der)

        merc_ca = load_pem_x509_certificate(merc_ca_pem, default_backend())

        self._validate_cert(merc_ca)

        self._merc_id = unhexlify(self._extract_merchant_id(merc_ca))
        self._private_key = load_pem_private_key(private_key_pem, None, default_backend())

    def _validate_cert(self, merc_ca):
        pass

    def _valid_signature(self, ephemeral_public_key, data, transaction_id, application_data = ''):
        s = b64decode(ephemeral_public_key) + b64decode(data) + b64decode(transaction_id + b64decode(application_data))
        return self._private_key.sign(s, ec.ECDSA(hashes.SHA256()))


    def _extract_merchant_id(self, cert_pem):
        for ext in cert_pem.extensions:
            if ext.oid.dotted_string == OID_MERCHANT_ID:
                return ext.value.value[2:]

        return None

    def _generate_symmetric_key(self, shared_secred):
        sha = sha256()
        sha.update(b'\0'*3)
        sha.update(b'\1')
        sha.update(shared_secred)
        sha.update(b'\x0did-aes256-GCM'+b'Apple'+self._merc_id)

        return sha.digest()

    def decrypt(self, ephemeral_public_key, cipher_data,  transaction_id = None, application_data = ''):

        if not transaction_id == None:
            sig = _validate_signature(ephemeral_public_key, cipher_data,  transaction_id , application_data)

        public_key = load_der_public_key(b64decode(ephemeral_public_key), default_backend())
        cipherdata = b64decode(cipher_data)
        shared_secred = self._private_key.exchange(ec.ECDH(), public_key)

        symmetric_key = self._generate_symmetric_key(shared_secred)

        mode = ciphers.modes.GCM(b'\0'*16, cipherdata[-16:], 16)
        decryptor = ciphers.Cipher(ciphers.algorithms.AES(symmetric_key), mode, backend=default_backend()).decryptor()

        return decryptor.update(cipherdata[:-16])+decryptor.finalize()

