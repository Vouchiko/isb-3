import os
import argparse
from encryption import Encrypt
from decryption import Decrypt


parser = argparse.ArgumentParser(description='encrypter')
parser.add_argument('file', type=str, help='your file')
parser.add_argument('mode', type=str, help='1 to encrypt or 2 to decrypt')
parser.add_argument('private_key', type=str, help='only for decrypt')
parser.add_argument('encrypt_sym_key', type=str, help='only for decrypt')
parser.add_argument('encrypt_sym_nonce', type=str, help='only for decrypt')
args = parser.parse_args()


if args.mode == "1":
    print('Encryption of data')
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

        rsa_k = enc.rsa_encryption(k, keys[1])
        rsa_n = enc.rsa_encryption(n, keys[1])
        f4 = open("crypted_sym_key.txt", "wb")
        f4.write(rsa_k)

        f5 = open("crypted_sym_nonce.txt", "wb")
        f5.write(rsa_n)
        print('Complete!')
    except NameError:
        print("Wrong file name")
    except FileNotFoundError:
        print("File not found")


if args.mode == "2":
    print('Decryption of data...')
    dec = Decrypt()
    try:
        f4 = open(args.encrypt_sym_key, "rb")
        k_c = f4.read()

        f5 = open(args.encrypt_sym_nonce, "rb")
        n_c = f5.read()
        private_key = dec.private_deserialization(args.private_key)
        k = dec.rsa_decryption(k_c, private_key)
        n = dec.rsa_decryption(n_c, private_key)

        f6 = open("encrypt_text.txt", "rb")
        text = f6.read()
        init = os.urandom(16)
        d_text = dec.simmetric_decryptor(text, k, init, n)
        d_text = dec.un_padding_t(d_text)

        f7 = open("decrypt_text.txt", "w")
        f7.write(d_text)
        print('Complete!')
    except ValueError:
        print("Some file is damaged")
        print("Please recreate the keys")
    except FileNotFoundError:
        print ("Something wrong with file names. Check it out")