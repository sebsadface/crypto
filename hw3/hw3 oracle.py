#!/usr/bin/python

# This code has been tested with Python 3.7.0 (with pip installed).
# To install the cryptography library, run the following two commands:
#     python -m pip install --upgrade pip
#     python -m pip install cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys

def PadOracle(ciphertext):
  if len(ciphertext) < 32 or len(ciphertext) % 16 != 0:
    return False
  # Do not cheat --- of course
  # ciphertexts can be decrypted using the hardcoded key,
  # but this is not the goal. OK? :)
  decryptor = Cipher(
    algorithms.AES(b"Sixteen byte key"),
    modes.CBC(ciphertext[:16]),
    backend=default_backend()
  ).decryptor()
  decrypted = decryptor.update(ciphertext[16:]) + decryptor.finalize()
  last = int(decrypted[-1])
  if last < 1 or last > 16:
    return False
  for i in range(last):
    if int(decrypted[-1 - i]) != last:
      return False
  return True

if len(sys.argv) < 1:
  print("You need to specify a file!")
  exit()

ciphertext = None
with open(sys.argv[1], "rb") as ciphertext_file:
  ciphertext = ciphertext_file.read()
# Please put the padding oracle attack here.
# The variable "ciphertext" contains the ciphertext.
# The plaintexts in the two example ciphertexts are English text in UTF-8.
# To decode *complete* UTF-8 sequences, use b'...'.decode('utf8').
# If you have multiple subsequences and would like to decode
# without first concatenating all of them, you can use the
# codecs library (https://docs.python.org/3/library/codecs.html).

plaintext = bytearray()
cipher_blocks = list()
for i in range(0, len(ciphertext), 16):
  cipher_blocks.append(ciphertext[i:i+16])

for block in range(len(cipher_blocks) - 1, 0, -1):
  current_cipher = cipher_blocks[block - 1] + cipher_blocks[block]
  recovered_block = bytearray(16)

  for byte in range(15, -1, -1):
    target_padding_value = 16 - byte
    valid_cipher_ending = bytearray() 

    for i in range(1, target_padding_value):
      valid_cipher_ending += bytearray.fromhex('{:02x}'.format(target_padding_value ^ recovered_block[byte + i]))

    for i in range(0, 256):
      x_xor_y = bytearray.fromhex('{:02x}'.format((i ^ current_cipher[byte])))
      test_cipher = current_cipher[:byte] + x_xor_y + valid_cipher_ending + current_cipher[byte + 1 + target_padding_value - 1:]
      validate_padding = test_cipher[:byte - 1] + bytearray.fromhex('{:02x}'.format((1 ^ test_cipher[byte])))  + test_cipher[byte:]
      
      if(PadOracle(test_cipher) and PadOracle(validate_padding)):
        recovered_block = recovered_block[:byte] + bytearray.fromhex('{:02x}'.format(test_cipher[byte] ^ target_padding_value)) + recovered_block[byte + 1:]
        plaintext = bytearray.fromhex('{:02x}'.format(i ^ target_padding_value)) + plaintext
        break

padding_num = plaintext[-1]
original_message = plaintext[:-padding_num].decode("utf-8")

print(original_message)