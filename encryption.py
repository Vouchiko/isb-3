import logging
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

    def generation_key(self) -> bytes:
        """key generation"""
        logging.info('Key generation...')
        key = os.urandom(32)
        return key

    def generation_nonce(self) -> bytes:
        """nonce generation"""
        logging.info('Nonce generation...')
        n = os.urandom(16)
        return n

    def key_serialization(self, patch: str, key: bytes) -> None:
        """
       serializing the symmetric algorithm key to a file

            Parameters:
                patch: file name
                key: key
        """
        logging.info('Serializing the symmetric algorithm key to a file...')
        with open(patch, 'wb') as key_file:
            key_file.write(key)

    def key_deserialization(self, patch: str, key: bytes) -> bytes:
        """
        Deserialization of the symmetric algorithm key

            Parameters:
                patch: file name
                key: key
            Return value:
                content: deserialized content
        """
        logging.info('Deserialization of the symmetric algorithm key...')
        with open(patch, mode='rb') as key_file:
            content: bytes = key_file.read()
        return content

    def padding_t(self, text: str) -> bytes:
        """
        Data padding for block cipher operation

            Parameters:
                text: text to be padded
            Return value:
                padded_text: text with padding applied to it
        """
        logging.info('Data padding for block cipher operation...')
        padders = padding.ANSIX923(32).padder()
        text = bytes(text, 'UTF-8')
        padded_text: bytes = padders.update(text) + padders.finalize()
        return padded_text

    def simmetric_cryptor(self, text: str, key: bytes, inizializer: bytes, nonce: bytes) -> bytes:
        """
        data encryption using symmetric algorithm

            Parameters:
                text: text for encrypting
                key: encryption key
                nonce: additional parameter
            Return value:
                c_text: encrypted text
        """
        logging.info('Data encryption using symmetric algorithm...')
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        c_text: bytes = encryptor.update(text) + encryptor.finalize()
        return c_text

    def rsa_key_generate(self) -> tuple:
        """
         generating a key pair for an asymmetric encryption algorithm

            Return value:
                private_key
                public_key
        """
        logging.info('Generating a key pair for an asymmetric encryption algorithm...')
        keys = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key = keys
        public_key = keys.public_key()
        return private_key, public_key

    def public_serialization(self, public_key) -> None:
        """
        serializing the public key to a file
            Parameters: public_key
        """
        logging.info('Serializing the public key to a file...')
        public_pem = 'Data/keys/public.pem'
        with open(public_pem, 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))

    def private_serialization(self, private_key) -> None:
        """
        serializing the private key to a file
            Parameters: public_key
        """
        logging.info('Serializing the private key to a file...')
        private_pem = 'Data/Encryption/private.pem'
        with open(private_pem, 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))

    def rsa_encryption(self, text: str, public_key: str) -> bytes:
        """
         text encryption using RSA-OAEP
            Parameters:
                text
                public_key
            Return value:
                c_text
        """
        logging.info('Text encryption using RSA-OAEP...')
        c_text = public_key.encrypt(text,
                                    pd.OAEP(mgf=pd.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                            label=None))
        return c_text


'''
This class provides methods for encrypting data
'''
