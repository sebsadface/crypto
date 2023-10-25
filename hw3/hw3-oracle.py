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
