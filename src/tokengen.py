# Searchable Encryption: Token Generation Module
# Authors: Jonathan Kenney (M08837382) and Brennan Thomas (M10668733)

# IMPORTS
import os
from sys import argv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# CONSTANTS
AES_BLOCK_SIZE = 16   # AES block size (bytes)

# HELPER FUNCTIONS
# encrypt a keyword with AES-ECB
def encKeyword(sk, word):

  m = word.encode('utf-8')

  # pad the data
  padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()   # NOTE: param here is block size in bits, not bytes
  m_padded = padder.update(m) + padder.finalize()

  # generate the AES cipher and encrpytor
  backend = default_backend()
  cipher = Cipher(algorithms.AES(sk), modes.ECB(), backend=backend)
  encryptor = cipher.encryptor()

  # generate the ciphertext and convert to hex
  ct = encryptor.update(m_padded) + encryptor.finalize()

  cword = ct.hex()

  return cword

# MAIN PROGRAM
def main():

  req = argv[1]

  # fetch the prfkey and convert from hex to bytes
  with open('./data/prfkey.txt', 'r') as f:
    prfkey = bytes.fromhex(f.read())
    f.close()

  token = encKeyword(prfkey, req)
  print('Search Request Token: %s' % token)

  with open('./data/token.txt', 'w') as f:
    f.write(token)
    f.close()


# main boilerplate
if __name__ == '__main__':
  main()