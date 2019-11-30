# Searchable Encryption: PRF and AES Key Generation
# Authors: Jonathan Kenney (M08837382) and Brennan Thomas (M########)

# imports
from sys import argv
from os import urandom


# main program
def main():
  
  # get key size from args
  try:
    key_size = int(argv[1])
  except:
    print('\nUsage:\npython3 keygen.py [KEY_SIZE]\n')
    exit(1)

  # check supplied key size
  if key_size not in (16, 24, 32):
    print('ERROR: Invalid key size, must be in {16, 24, 32}\n')
    exit(1)

  # returns random keys (bytes) from OS and converts to hex
  prfkey = urandom(key_size).hex()
  aeskey = urandom(key_size).hex()

  # store prfkey (in hex) in file
  with open('./data/prfkey.txt', 'w') as f:
    f.write(prfkey)
    f.close()

  # store aeskey (in hex) in file
  with open('./data/aeskey.txt', 'w') as f:
    f.write(aeskey)
    f.close()

  return

# main boilerplate
if __name__ == '__main__':
  main()