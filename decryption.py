from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as pd
from cryptography.hazmat.primitives import hashes


class Decrypt:
    def __init__(self):
        pass

    def un_padding_t(self, dc_text):
        unpadder = padding.ANSIX923(32).unpadder()
        unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
        return unpadded_dc_text.decode('UTF-8')

    def simmetric_decryptor(self, text, key, inizializer, nonc):
        cipher = Cipher(algorithms.ChaCha20(key, nonc), mode=None)
        decryptor = cipher.decryptor()
        dc_text = decryptor.update(text) + decryptor.finalize()
        return dc_text

    def public_deserialization(self, public_pem):
        with open(public_pem, 'rb') as pem_in:
            public_bytes = pem_in.read()
        d_public_key = load_pem_public_key(public_bytes)
        return d_public_key

    def private_deserialization(self, private_pem):
        with open(private_pem, 'rb') as pem_in:
            private_bytes = pem_in.read()
        d_private_key = load_pem_private_key(private_bytes, password=None, )
        return d_private_key

    def rsa_decryption(self, c_text, private_key):
        dc_text = private_key.decrypt(c_text, pd.OAEP(mgf=pd.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                      label=None))
        return dc_text