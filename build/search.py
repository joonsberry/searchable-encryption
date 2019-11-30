# Searchable Encryption: Search and Decryption Module
# Author: Jonathan Kenney (M08837382) and Brennan Thomas (M########)

# IMPORTS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# CONSTANTS
AES_BLOCK_SIZE = 16   # AES block size (bytes)

# HELPER FUNCTIONS
# encrypt a keyword with AES-ECB
def buildIndexFromString(index_string):

  index = {}

  lines = index_string.split('\n')

  for l in lines:
    l_split = l.split(':')
    index[l_split[0]] = [c for c in l_split[1].split(',')]

  return index

def decFile(sk, iv, ct):

  # generate the AES cipher and decrpytor
  backend = default_backend()
  cipher = Cipher(algorithms.AES(sk), modes.CBC(iv), backend=backend)
  decryptor = cipher.decryptor()

  # decrypt the ciphertext and decode
  m_padded = decryptor.update(ct) + decryptor.finalize()

  # unpad the data
  unpadder = padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()   # NOTE: param here is block size in bits, not bytes
  m = unpadder.update(m_padded) + unpadder.finalize()

  return m.decode('utf-8')

# MAIN PROGRAM
def main():

  aeskey = b''
  iv = b''
  token = ''
  index_string = ''

  # fetch the aeskey and convert from hex to bytes
  with open('./data/aeskey.txt', 'r') as f:
    aeskey = bytes.fromhex(f.read())
    f.close()

  # fetch the iv and convert from hex to bytes
  with open('./data/iv.txt', 'r') as f:
    iv = bytes.fromhex(f.read())
    f.close()

  # fetch the token in hex
  with open('./data/token.txt', 'r') as f:
    token = f.read()
    f.close()

  # fetch the index string
  with open('./data/index.txt', 'r') as f:
    index_string = f.read()
    f.close()

  index = buildIndexFromString(index_string)

  ctfnames = ''
  dec_table = ''
  
  for ctfname in index[token]:
    
    with open('./data/ciphertextfiles/' + ctfname, 'r') as f:
  
      ctfnames = ctfnames + ctfname + ' '
      
      ct = bytes.fromhex(f.read())
      m = decFile(aeskey, iv, ct)
      dec_table = dec_table + ctfname + ': ' + m + '\n'
  
      f.close()

  with open('./data/result.txt', 'w') as f:
    f.write(ctfnames + '\n\n' + dec_table)
    f.close()

  return

# main boilerplate
if __name__ == '__main__':
  main()