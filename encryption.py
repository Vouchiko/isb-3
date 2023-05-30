import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as pd

'''
This class provides methods for encrypting data
'''


class Encrypt:
    def __init__(self):
        pass

    def generation_key(self):

        """key generation"""

        key = os.urandom(32)
        return key

    def generation_nonce(self):

        """nonce generation"""

        n = os.urandom(16)
        return n

    def key_serialization(self, patch, key):
        """
        serializing the symmetric algorithm key to a file

            Parameters:
                patch: file name
                key: key
        """
        with open(patch, 'wb') as key_file:
            key_file.write(key)

    def key_deserialization(self, patch, key):
        """
        deserialization of the symmetric algorithm key

            Parameters:
                patch: file name
        """
        with open(patch, mode='rb') as key_file:
            content = key_file.read()
        return content

    def padding_t(self, text):
        """
        data padding for block cipher operation

            Parameters:
                text: text
            Return value:
                padded_text: text with padding applied to it
        """
        padders = padding.ANSIX923(32).padder()
        text = bytes(text, 'UTF-8')
        padded_text = padders.update(text) + padders.finalize()
        return padded_text

    def simmetric_cryptor(self, text, key, inizializer, nonce):
        """
        data padding for block cipher operation

            Parameters:
                text: text for encrypting
                key: encryption key
                nonce: Additional parameter
            Return value:
                c_text: encrypted text
        """
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        c_text = encryptor.update(text) + encryptor.finalize()
        return c_text

    def rsa_key_generate(self):
        """
         generating a key pair for an asymmetric encryption algorithm

            Return value:
                private_key
                public_key
        """
        keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key = keys
        public_key = keys.public_key()
        return private_key, public_key

    def public_serialization(self, public_key):
        """
        serializing the public key to a file
            Parameters: public_key
        """
        public_pem = 'Data/keys/public.pem'
        with open(public_pem, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))

    def private_serialization(self, private_key):
        """
        serializing the private key to a file
            Parameters: public_key
        """
        private_pem = 'Data/Encryption/private.pem'
        with open(private_pem, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))

    def rsa_encryption(self, text, public_key):
        """
         text encryption using RSA-OAEP
            Parameters:
                text
                public_key
            Return value:
                c_text
        """
        c_text = public_key.encrypt(text,
                                    pd.OAEP(mgf=pd.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                            label=None))
        return c_text
