import random
from cryptography.fernet import Fernet
import base64
import argparse
import time


BLOCK_SIZE = 64
random.seed(BLOCK_SIZE)
IV = [random.randint(0, 255) for _ in range(BLOCK_SIZE)]
random.seed()


def gen_key():
    a = [i for i in range(256)]
    random.shuffle(a)
    return a


def reverse_key(a):
    return [a.index(i) for i in range(256)]


def gen_pass(pwd_=None):
    if not pwd_:
        pwd_ = ''.join(random.sample('qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890!@#$%^&*()-_=+,.<>/?', 32))
    else:
        while len(pwd_) < 32:
            pwd_ += pwd_[:32-len(pwd_)]
    return pwd_, base64.b64encode(pwd_.encode())


def xor(a, b):
    if len(a) != len(b):
        raise ValueError('List\'s lengths must be equal')
    return [a[i] ^ b[i] for i in range(len(a))]


def encrypt(data, key, filename_):
    res = []
    def encrypt_block(_block):
        return [key[_block[i]] for i in range(BLOCK_SIZE)]
    blocks = [list(data[x:x+BLOCK_SIZE]) for x in range (0, len(data), BLOCK_SIZE)]
    last_block_len = len(blocks[-1])
    prev_block = IV
    if  last_block_len < BLOCK_SIZE:
        blocks[-1] += [0 for _ in range(BLOCK_SIZE - last_block_len)]
    for block in blocks:
        xored = xor(block, prev_block)
        encrypted = encrypt_block(xored)
        prev_block = encrypted
        res += encrypted
    return res


def decrypt(data, key):
    res = []
    def decrypt_block(_block):
        return [key[_block[i]] for i in range(BLOCK_SIZE)]
    blocks = [list(data[x:x+BLOCK_SIZE]) for x in range (0, len(data), BLOCK_SIZE)]
    last_block_len = len(blocks[-1])
    prev_block = IV
    if  last_block_len < BLOCK_SIZE:
        blocks[-1] += [0 for _ in range(BLOCK_SIZE - last_block_len)]
    for block in blocks:
        decrypted = decrypt_block(block)
        xored = xor(decrypted, prev_block)
        res += xored
        prev_block = block
    while res[-1] == 0:
        res = res[:-1]
    return res


if __name__ == '__main__':
    t1 = time.time()
    parser = argparse.ArgumentParser(description='Encrypt/decrypt files')
    parser.add_argument("-m", dest="mode", required=True, help='d for decrypt, e for encrypt')
    parser.add_argument("-f", dest="file", required=True, help='file')
    parser.add_argument("-k", dest="key", help='own key')
    parser.add_argument("-o", dest="outfile", help='output file')
    args = parser.parse_args()
    mode = args.mode
    file = args.file
    outfile = args.outfile
    data = open(file, 'rb').read()
    key = args.key
    if key:
        key_e = list(base64.b64decode(key))
    else:
        key_e = gen_key()
    key_d = reverse_key(key_e)

    if mode == 'd':
        if not key:
            print('No key provided!')
            exit(1)

        dec = decrypt(data, key_d)
        if outfile:
            filename = outfile
        else:
            filename = file.replace('.enc', '')
        with open(filename, 'wb') as file_:
            file_.write(bytes(dec))

    elif mode == 'e':
        print(f'Your key: {base64.b64encode(bytes(key_e)).decode()}')

        if outfile:
            filename = outfile
        else:
            filename = file+'.enc'
        enc = encrypt(data, key_e, filename)
        with open(filename, 'wb') as file_:
            file_.write(bytes(enc))
    else:
        pass

print(f'Runtime: {time.time() - t1}')