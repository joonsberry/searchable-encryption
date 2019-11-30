# Searchable Encryption: Encryption Module
# Author: Jonathan Kenney (M08837382) and Brennan Thomas (M########)

# IMPORTS
import os
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# CONSTANTS
AES_BLOCK_SIZE = 16   # AES block size (bytes)

# HELPER FUNCTIONS
# encrypt a keyword with AES-ECB
def encKeyword(sk, word):

  print(word)

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

# encrypt a keyword with AES-CBC
def encFile(sk, iv, fi):

  m = b''

  # fetch message from plaintext file and convert to bytes
  with open(fi.path, 'r') as f:
    m = f.read().encode('utf-8')
    f.close()

  # pad the data
  padder = padding.PKCS7(AES_BLOCK_SIZE * 8).padder()   # NOTE: param here is block size in bits, not bytes
  m_padded = padder.update(m) + padder.finalize()

  # generate the AES cipher and encrpytor
  backend = default_backend()
  cipher = Cipher(algorithms.AES(sk), modes.CBC(iv), backend=backend)
  encryptor = cipher.encryptor()

  # generate the ciphertext and convert to hex
  ct = encryptor.update(m_padded) + encryptor.finalize()

  ctfname = 'c' + fi.name[1] + '.txt'

  # write ciphertext to file in hex
  with open('./data/ciphertextfiles/' + ctfname, 'w') as f:
    f.write(ct.hex())
    f.close()

  return ctfname

# build encrypted inverted index
def buildIndex(dir_path, prfkey, aeskey, iv):

  index = {}

  # loop through each plaintext file in files directory
  for fi in os.scandir(dir_path):

    # get encrypted file
    ctfname = encFile(aeskey, iv, fi)
    
    # open file and split words on whitespace
    with open(fi.path, 'r') as f:
      words = f.read().split(' ')
      
      # strip any punctuation and add this filename to index value for this keyword
      for word in words:
        word = re.sub(r'[^\w\s]','',word)
        
        # encrypt the keyword
        cword = encKeyword(prfkey, word)

        # if word not already key for index then create new key
        if cword not in index:
          index[cword] = []

        # append this file to list for this keyword
        index[cword].append(ctfname)

  return index

# MAIN PROGRAM
def main():

  # initialize vars
  prfkey = b''
  aeskey = b''
  
  # fetch the prfkey and convert from hex to bytes
  with open('./data/prfkey.txt', 'r') as f:
    prfkey = bytes.fromhex(f.read())
    f.close()

  # fetch the aeskey and convert from hex to bytes
  with open('./data/aeskey.txt', 'r') as f:
    aeskey = bytes.fromhex(f.read())
    f.close()

  # generate CBC initialization vector
  iv = os.urandom(AES_BLOCK_SIZE)

  # build and return the encrypted index
  index = buildIndex('./data/files', prfkey, aeskey, iv)

  # format string to write index to text file
  write_string = ''
  for key in index.keys():
    write_string = write_string + key + ':'
    for ctfname in index[key]:
      write_string = write_string + ctfname + ','
    write_string = write_string[:-1]
    write_string = write_string + '\n'
  write_string = write_string[:-1]


  # write encrypted index to text file
  with open('./data/index.txt', 'w') as f:
    f.write(write_string)
    f.close()

  # write iv to file in hex
  with open('./data/iv.txt', 'w') as f:
    f.write(iv.hex())
    f.close()


# main boilerplate
if __name__ == '__main__':
  main()