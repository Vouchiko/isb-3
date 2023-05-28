import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as pd


class Encrypt:
    def __init__(self):
        pass

    def generation_key(self):
        key = os.urandom(32)
        return key

    def generation_nonce(self):
        n = os.urandom(16)
        return n

    def key_serialization(self, patch, key):
        with open(patch, 'wb') as key_file:
            key_file.write(key)

    def key_deserialization(self, patch, key):
        with open(patch, mode='rb') as key_file:
            content = key_file.read()
        return content

    def padding_t(self, text):
        padders = padding.ANSIX923(32).padder()
        text = bytes(text, 'UTF-8')
        padded_text = padders.update(text) + padders.finalize()
        return padded_text

    def simmetric_cryptor(self, text, key, inizializer, nonc):
        cipher = Cipher(algorithms.ChaCha20(key, nonc), mode=None)
        encryptor = cipher.encryptor()
        c_text = encryptor.update(text) + encryptor.finalize()
        return c_text

    def rsa_key_generate(self):
        keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key = keys
        public_key = keys.public_key()
        return private_key, public_key

    def public_serialization(self, public_key):
        public_pem = 'keys/public.pem'
        with open(public_pem, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))

    def private_serialization(self, private_key):
        private_pem = 'private.pem'
        with open(private_pem, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))

    def rsa_encription(self, text, public_key):
        c_text = public_key.encrypt(text,
                                    pd.OAEP(mgf=pd.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                            label=None))
        return c_text