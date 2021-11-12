import random
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


def encrypt(key, filename_in=None, filename_out=None):
    def encrypt_block(_block):
        return [key[_block[i]] for i in range(BLOCK_SIZE)]
    
    with open(filename_in, 'rb') as file:
        out_file = open(filename_out, 'wb')
        prev_block = IV
        while True:
            block = list(file.read(BLOCK_SIZE))
            if not block:
                break
            if len(block) < BLOCK_SIZE:
                block += [0 for _ in range(BLOCK_SIZE - len(block))]
            xored = xor(block, prev_block)
            encrypted = encrypt_block(xored)
            prev_block = encrypted
            out_file.write(bytes(encrypted))
        out_file.close()


def decrypt(key, filename_in=None, filename_out=None):
    def decrypt_block(_block):
        return [key[_block[i]] for i in range(BLOCK_SIZE)]
    
    with open(filename_in, 'rb') as file:
        out_file = open(filename_out, 'wb')
        prev_block = IV
        while True:
            block = list(file.read(BLOCK_SIZE))
            # while block[-1] == 0:
            #     block = block[:-1]
            if not block:
                break
            decrypted = decrypt_block(block)
            xored = xor(decrypted, prev_block)
            out_file.write(bytes(xored))
            prev_block = block


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
    key = args.key
    if key:
        key_e = list(base64.b64decode(key))
    else:
        key_e = gen_key()
    key_d = reverse_key(key_e)
    for i in range(256):
        if i not in key_d:
            print(i)

    if mode == 'd':
        if not key:
            print('No key provided!')
            exit(1)

        if outfile:
            filename = outfile
        else:
            filename = file.replace('.enc', '')
        dec = decrypt(key_d, file, filename)

    elif mode == 'e':
        print(f'Your key: {base64.b64encode(bytes(key_e)).decode()}')

        if outfile:
            enc = encrypt(key_e, file, outfile)
        else:
            enc = encrypt(key_e, file, file+'.enc')
        
        # with open(filename, 'wb') as file_:
        #     file_.write(bytes(enc))
    else:
        pass

print(f'Runtime: {time.time() - t1}')