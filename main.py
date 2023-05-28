import os
import argparse
from encryption import Encrypt
from decryption import Decrypt


parser = argparse.ArgumentParser(description='encripter')
parser.add_argument('file', type=str, help='your file')
parser.add_argument('mode', type=str, help='1 to encript or 2 to decript')
args = parser.parse_args()


if args.mode == "1":
    enc = Encrypt()
    try:
        f_in = open(args.file)
        s = f_in.read()
        k = enc.generation_key()
        n = enc.generation_nonce()
        print('Key Serialization...')
        enc.key_serialization("keys/key.txt", k)
        print('Serialization of an additional parameter...')
        enc.key_serialization("keys/nonce.txt", n)
        print('Data encryption...')
        f1 = open("keys/key.txt", "rb")
        f2 = open("keys/nonce.txt", "rb")
        k = f1.read()
        n = f2.read()
        sp = enc.padding_t(s)
        init = os.urandom(16)
        cs = enc.simmetric_cryptor(sp, k, init, n)
        f3 = open("encrypt_text.txt", "wb")
        f3.write(cs)
        keys = enc.rsa_key_generate()
        enc.public_serialization(keys[1])
        enc.private_serialization(keys[0])

        rsa_k = enc.rsa_encription(k, keys[1])
        rsa_n = enc.rsa_encription(n, keys[1])
        f4 = open("crypted_sym_key.txt", "wb")
        f4.write(rsa_k)

        f5 = open("crypted_sym_nonce.txt", "wb")
        f5.write(rsa_n)
        print('Complete!')
    except NameError:
        print("Wrong file name")
    except FileNotFoundError:
        print("File not found")

