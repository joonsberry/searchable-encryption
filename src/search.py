# Searchable Encryption: Search and Decryption Module
# Author: Jonathan Kenney (M08837382) and Brennan Thomas (M########)

# imports
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# constants
AES_BLOCK_SIZE = 16   # AES block size (bytes)