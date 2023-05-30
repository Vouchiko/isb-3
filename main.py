import os
import argparse
from encryption import Encrypt
from decryption import Decrypt


parser = argparse.ArgumentParser(description='encrypter')
parser.add_argument('file', type=str, help='your file')
parser.add_argument('mode', type=str, help='1 to generate or 2 to encrypt or 3 to decrypt')
parser.add_argument('private_key', type=str, help='only for decrypt')
parser.add_argument('encrypt_sym_key', type=str, help='only for decrypt')
parser.add_argument('encrypt_sym_nonce', type=str, help='only for decrypt')
args = parser.parse_args()


if args.mode == "1":
    print('Generation...')
    enc = Encrypt()

    k = enc.generation_key()
    n = enc.generation_nonce()
    print('Key Serialization...')
    enc.key_serialization("Data/keys/key.txt", k)
    print('Serialization of an additional parameter...')
    enc.key_serialization("Data/keys/nonce.txt", n)
    print('Complete!')


if args.mode == "2":
    print('Encryption of data')
    enc = Encrypt()
    try:
        with open(args.file) as f_in:
            s = f_in.read()
            print('Data encryption...')
        with open("Data/keys/key.txt", "rb") as f1, open("Data/keys/nonce.txt", "rb") as f2:
            k = f1.read()
            n = f2.read()
            sp = enc.padding_t(s)
            init = os.urandom(16)
            cs = enc.simmetric_cryptor(sp, k, init, n)
        with open("Data/Encryption/encrypt_text.txt", "wb") as f3:
            f3.write(cs)
            keys = enc.rsa_key_generate()
            enc.public_serialization(keys[1])
            enc.private_serialization(keys[0])

            rsa_k = enc.rsa_encryption(k, keys[1])
            rsa_n = enc.rsa_encryption(n, keys[1])
        with open("Data/Encryption/crypted_sym_key.txt", "wb") as f4:
            f4.write(rsa_k)

        with open("Data/Encryption/crypted_sym_nonce.txt", "wb") as f5:
            f5.write(rsa_n)
        print('Complete!')
    except NameError:
        print("Wrong file name")
    except FileNotFoundError:
        print("File not found")


if args.mode == "3":
    print('Decryption of data...')
    dec = Decrypt()
    try:
        with open(args.encrypt_sym_key, "rb") as f4:
            k_c = f4.read()

        with open(args.encrypt_sym_nonce, "rb") as f5:
            n_c = f5.read()
            private_key = dec.private_deserialization(args.private_key)
            k = dec.rsa_decryption(k_c, private_key)
            n = dec.rsa_decryption(n_c, private_key)

        with open("Data/Encryption/encrypt_text.txt", "rb") as f6:
            text = f6.read()
            init = os.urandom(16)
            d_text = dec.simmetric_decryptor(text, k, init, n)
            d_text = dec.un_padding_t(d_text)

        with open("Data/Decryption/decrypt_text.txt", "w") as f7:
            f7.write(d_text)
        print('Complete!')
    except ValueError:
        print("Some file is damaged")
        print("Please recreate the keys")
    except FileNotFoundError:
        print("Something wrong with file names. Check it out")
