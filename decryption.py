import logging

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.asymmetric import padding as pd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa


class Decrypt:
    def __init__(self):
        pass

    def un_padding_t(self, dc_text: bytes) -> str:
        """
        unpadding of text by a symmetric algorithm

            Parameters:
               dc_text: text for unpadding
            Return value:
                unpadded_dc_text.decode(): The text with the unpadding algorithm applied to it
        """
        logging.info('Unpadding of text by a symmetric algorithm...')
        unpadder = padding.ANSIX923(32).unpadder()
        unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
        return unpadded_dc_text.decode('UTF-8')

    def simmetric_decryptor(self, text: bytes, key: bytes, inizializer: bytes, nonce: bytes) -> bytes:
        """
        Decryption of text by symmetric algorithm

            Parameters:
                text: text for decrypting
                key: encryption key
                nonce: Additional parameter
            Return value:
                dc_text: The text with the decrypting algorithm applied to it
        """
        logging.info('Decryption of text by symmetric algorithm...')
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        decryptor = cipher.decryptor()
        dc_text = decryptor.update(text) + decryptor.finalize()
        return dc_text

    def public_deserialization(self, public_pem: str) -> rsa.RSAPublicKey:
        """
        Deserializing the public key

            Parameters:
                public_pem: public key
            Return value:
                d_public_key: deserialized public key
        """
        logging.info('Deserializing the public key...')
        with open(public_pem, 'rb') as pem_in:
            public_bytes = pem_in.read()
        d_public_key = load_pem_public_key(public_bytes)
        return d_public_key

    def private_deserialization(self, private_pem: str) -> rsa.RSAPrivateKey:
        """
        Deserializing the private key

            Parameters:
                private_pem: private key
            Return value:
                d_private_key: deserialized private key
        """
        logging.info('Deserializing the private key...')
        with open(private_pem, 'rb') as pem_in:
            private_bytes = pem_in.read()
        d_private_key = load_pem_private_key(private_bytes, password=None, )
        return d_private_key

    def rsa_decryption(self, c_text: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """
        Decryption of the text by an asymmetric algorithm

            Parameters:
                c_text: Encrypted text
                private_key: private key
            Return value:
                dc_text: decrypted text

        """
        logging.info('Decryption of the text by an asymmetric algorithm...')
        dc_text = private_key.decrypt(c_text, pd.OAEP(mgf=pd.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                      label=None))
        return dc_text


'''
This class provides methods for decrypting data
'''
