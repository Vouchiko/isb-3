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
