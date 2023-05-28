import os


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