import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from time import sleep
from timeit import default_timer as timer

def EtMEncrypt(key_enc,key_mac, pt):
    backend = default_backend()
    iv = os.urandom(16)
    algorithm = algorithms.ChaCha20(key_enc, iv)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(pt) + encryptor.finalize()
    h = hmac.HMAC(key_mac, hashes.SHA256(), backend=default_backend())
    h.update(iv+ct)
    tag = h.finalize()
    final = iv + ct + tag[:8]
    return final

def EtMDecrypt(key_enc,key_mac, ct):
    backend = default_backend()
    h = hmac.HMAC(key_mac, hashes.SHA256(), backend=default_backend())
    h.update(ct[:-8])
    tag = h.finalize()[:8]
    if CheckEq(tag,ct[-8:]):
        iv = ct[:16]
        algorithm = algorithms.ChaCha20(key_enc, iv)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        pt = decryptor.update(ct[16:-8]) + decryptor.finalize()
        return pt
    raise Exception('authentication failure')

def CheckEq(a, b):
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        sleep(0.005)
        if a[i] != b[i]:
            return False
    sleep(0.005)
    return True

def EtMOracle(ct):
    backend = default_backend()
    h = hmac.HMAC(key_mac, hashes.SHA256(), backend=default_backend())
    h.update(ct[:-8])
    tag = h.finalize()[:8]
    if CheckEq(tag,ct[-8:]):
        return True
    return False

key_enc = os.urandom(32)
key_mac = os.urandom(16)


cipher = EtMEncrypt(key_enc, key_mac, b"Hello world!")

# =======================
# Insert your attack below this line.
# Do not modify above this line.
def measure_baseline_time(oracle, cipher, byte_index, trials=100):
    total_time = 0
    test_cipher = cipher
    if byte_index > 0:
        wrong_tag = b'\xff' * byte_index  
        test_cipher = cipher[:-byte_index] + wrong_tag

    for _ in range(trials):
        start = timer()
        oracle(test_cipher)
        end = timer()
        total_time += (end - start)

    return total_time / trials


def modify_cipher_text(cipher, original="Hello world!", new="Hello folks!"):
    # XOR the original and new text to get the XOR difference
    xor_diff = bytes([a ^ b for a, b in zip(original.encode(), new.encode())])

    # Apply this XOR difference to the corresponding part of the cipher text
    modified_cipher = bytearray(cipher)
    start_index = 16 

    for i, byte in enumerate(xor_diff):
        modified_cipher[start_index + i] ^= byte

    return bytes(modified_cipher)

def guess_tag_byte(oracle, altered_cipher, guessed_tag, byte_index, baseline_time):
    correct_guess = 0
  
    while correct_guess == 0:
        for guess in range(256):
            guessed_tag[byte_index] = guess
            test_cipher = altered_cipher[:-8] + guessed_tag

            start = timer()
            oracle(test_cipher)
            end = timer()
            time = (end - start)

            if time * 1.01 >= baseline_time :
                total_time = 0
                for _ in range (100):
                    start = timer()
                    oracle(test_cipher)
                    end = timer()
                    total_time += (end - start)
                avg = total_time / 100

               
                if (avg * 1.01 >= baseline_time ):
                    print(f"Byte {byte_index}, Guess {guess}, Time: {avg}") 
                    print()
                    correct_guess = guess
                    break
                continue 
    
    return correct_guess

beginning = timer()

guessed_tag = bytearray(8)
altered_cipher = modify_cipher_text(cipher, original="Hello world!", new="Hello folks!")

for i in range(8):
    baseline_time = measure_baseline_time(EtMOracle, cipher, 7 - i)
    print(f"Baseline Time: {baseline_time}") 
    guessed_tag[i] = guess_tag_byte(EtMOracle, altered_cipher, guessed_tag, i, baseline_time)
    print(f"Guessed Tag So Far: {guessed_tag.hex()}") 
cipher_forged = altered_cipher[:-8] + guessed_tag
ending = timer()
print()
print(f"Total Time: {ending - beginning}")  

# Insert the attack above this line.
# Do not mofidy below this line.
# =======================

pt = EtMDecrypt(key_enc, key_mac, cipher_forged)
print(pt)