#!/usr/bin/python

# This code has been tested with Python 3.7.0 (with pip installed).
# To install the cryptography library, run the following two commands:
#     python -m pip install --upgrade pip
#     python -m pip install cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def EvalAES(K, X):
  """
  Given the key K and the input X, evaluates AES-128 and returns the output Y.
  """
  cipher = Cipher(algorithms.AES(K), modes.ECB(), backend=default_backend())
  enc = cipher.encryptor()
  Y = enc.update(X) + enc.finalize()
  return Y

def InvertAES(K, Y):
  """
  Given the key K and the output Y, inverts AES-128 and returns the input X.
  """
  cipher = Cipher(algorithms.AES(K), modes.ECB(), backend=default_backend())
  dec = cipher.decryptor()
  X = dec.update(Y) + dec.finalize()
  return X

def FindK(X):
    K = os.urandom(16)
    C = EvalAES(K, X)
    while C.hex()[-2:] != '00':
        K = os.urandom(16)
        C = EvalAES(K, X)
        print("C = " + C.hex())
    return K

# Sample usage
#             K = ab cd ab cd ab cd ab cd 01 01 01 01 01 01 01 01
#             X = 12 34 12 34 12 34 12 34 12 34 12 34 12 34 12 34
# Y = AES(K, X) = 25 73 7d b5 d3 1b de 43 8b 2c c9 67 7b 2d 7f 3b
K = b'\x10\x04\x20\x18' + 12 * b'\x00'
X = b'\x10\x04\x20\x18' + 12 * b'\x00'
Y = EvalAES(K, X)
C = b'\x00' * 16
M = InvertAES(K, C)
print("              K = " + K.hex())
print("              X = " + X.hex())
print("  Y = AES(K, X) = " + Y.hex())
print("AES^(-1) (K, Y) = " + InvertAES(K, Y).hex())
print("AES^(-1) (K, C) = " + M.hex())
print("  C = AES(K, M) = " + EvalAES(K, M).hex())

print("")
print("Everything fine." if InvertAES(K, Y) == X else "What?!")

print("")
print("Found K = " + FindK(X).hex())
