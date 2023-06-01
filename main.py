import os
import argparse
import logging
import json
from encryption import Encrypt
from decryption import Decrypt

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='encrypter')
    parser.add_argument('mode', type=str, help='1 to generate or 2 to encrypt or 3 to decrypt')
    parser.add_argument('config', type=str, help='name of config file')
    args = parser.parse_args()

    logging.basicConfig(filename='Info.log', level=logging.INFO)

    with open(args.config, 'r') as f:
        config = json.load(f)
        key_file = config.get('key_file')
        nonce_file = config.get('nonce_file')
        if args.mode == "1":
            logging.info('Generation process:')
            enc = Encrypt()

            k = enc.generation_key()
            n = enc.generation_nonce()
            logging.info('Key Serialization...')
            enc.key_serialization(key_file, k)
            logging.info('Serialization of an additional parameter...')
            enc.key_serialization(nonce_file, n)
            logging.info('Complete!\n')

        encrypt_text_file = config.get('encrypt_text_file')
        encrypted_sym_key_file = config.get('encrypted_sym_key_file')
        encrypted_sym_nonce_file = config.get('encrypted_sym_nonce_file')
        if args.mode == "2":
            logging.info('Encryption of data')
            enc = Encrypt()
            try:
                with open(config.get('main_text')) as f_in:
                    s = f_in.read()
                with open(key_file, "rb") as f1, open(nonce_file, "rb") as f2:
                    k = f1.read()
                    n = f2.read()
                    sp = enc.padding_t(s)
                    init = os.urandom(16)
                    cs = enc.simmetric_cryptor(sp, k, init, n)
                with open(encrypt_text_file, "wb") as f3:
                    f3.write(cs)
                    keys = enc.rsa_key_generate()
                    enc.public_serialization(keys[1])
                    enc.private_serialization(keys[0])

                    rsa_k = enc.rsa_encryption(k, keys[1])
                    rsa_n = enc.rsa_encryption(n, keys[1])
                with open(encrypted_sym_key_file, "wb") as f4:
                    f4.write(rsa_k)

                with open(encrypted_sym_nonce_file, "wb") as f5:
                    f5.write(rsa_n)
                logging.info('Complete!\n')
            except NameError:
                logging.error("Wrong file name")
            except FileNotFoundError:
                logging.error("File not found")

        decrypt_text_file = config.get('decrypt_text_file')
        if args.mode == "3":
            logging.info('Decryption of data...')
            dec = Decrypt()
            try:
                with open(config.get('encrypt_symmetric_key'), "rb") as f4:
                    k_c = f4.read()

                with open(config.get('encrypt_symmetric_nonce'), "rb") as f5:
                    n_c = f5.read()
                    private_key = dec.private_deserialization(config.get('private_key'))
                    k = dec.rsa_decryption(k_c, private_key)
                    n = dec.rsa_decryption(n_c, private_key)

                with open(encrypt_text_file, "rb") as f6:
                    text = f6.read()
                    init = os.urandom(16)
                    d_text = dec.simmetric_decryptor(text, k, init, n)
                    d_text = dec.un_padding_t(d_text)

                with open(decrypt_text_file, "w") as f7:
                    f7.write(d_text)
                logging.info('Decryption completed successfully!\n')
            except ValueError:
                logging.error("Some file is damaged")
                logging.error("Please recreate the keys")
            except FileNotFoundError:
                logging.error("Something wrong with file names. Check it out")
