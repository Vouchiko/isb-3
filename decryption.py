from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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