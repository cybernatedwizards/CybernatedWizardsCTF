#/usr/bin/env python
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import hashlib
import os
import base64
from gmpy2 import is_prime

class Rng:
  def __init__(self, seed):
    self.seed = seed
    self.generated = b""
    self.num = 0

  def more_bytes(self):
    self.generated += hashlib.sha256(self.seed).digest()
    # increase seed by 1 and ensure the seed is 32 bytes long (prepend with NULL bytes)
    self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
    self.num += 256

  def getbits(self, num=64):
    while (self.num < num):
      self.more_bytes()
    x = bytes_to_long(self.generated)
    self.num -= num
    self.generated = b""

    # this is not called for our primes
    if self.num > 0:
      self.generated = long_to_bytes(x >> num, self.num // 8)

    # ANDs with 0xffff...ffff to ensure only a NUM length number is returned
    return x & ((1 << num) - 1)

class DiffieHellman:
  def gen_prime(self):
    prime = self.rng.getbits(512)
    iter = 0
    while not is_prime(prime):
      iter += 1
      prime = self.rng.getbits(512)
    print("Generated after", iter, "iterations")
    return prime

  def __init__(self, seed, prime=None):
    self.rng = Rng(seed)
    if prime is None:
      prime = self.gen_prime()

    self.prime = prime
    self.my_secret = self.rng.getbits()
    self.my_number = pow(5, self.my_secret, prime)
    self.shared = 1337

  def set_other(self, x):
    self.shared ^= pow(x, self.my_secret, self.prime)

def pad32(x):
  return (b"\x00"*32+x)[-32:]

def xor32(a, b):
  return bytes(x^y for x, y in zip(pad32(a), pad32(b)))

def bit_flip(x):
  print("bit-flip str:")
  inputstr = b'BA=='
  #inputstr = input().strip()
  flip_str = base64.b64decode(inputstr)
  return xor32(flip_str, x)


def get_values(conn, value):
    # receive the bit-flip str:
    conn.recvline()

    # send the value
    conn.send(value + b'\n')

    # recv num iterations
    num_iter = str(conn.recvline())
    bob_num = conn.recvline()
    iv_num = conn.recvline()
    flag_num = conn.recvline()

    results = [
        int(num_iter.split(" ")[2:3][0]),
        int(bob_num.decode('ascii').split(" ")[2:3][0]),
        base64.b64decode(iv_num.decode('ascii')),
        base64.b64decode(flag_num.decode('ascii'))
    ]
    return results

def get_num_iter(conn, value):
    return get_values(conn, value)[0]

def get_seed(conn):
    # loop over each bit of 64-bit number
    sol = 0
    maxnum = 128 # 128
    for i in range(1, maxnum):
        # get two values one with and without the ith bit set
        n = sol ^ ((2 ** i) - 2)
        m = sol | (1 << i)

        # base64 encode values
        basen = base64.b64encode(bytes(long_to_bytes(n)))
        basem = base64.b64encode(bytes(long_to_bytes(m)))
        iter_n = get_num_iter(conn, basen)
        iter_m = get_num_iter(conn, basem)
        print("N: %s [%d], M: %s [%d]" % (basen, iter_n, basem, iter_m))

        if(iter_n != iter_m + 1):
            sol = sol | (1 << i)
        print("SOL:" + " "*(135-maxnum) + bin(sol)[2:])

    return long_to_bytes(sol, 16)

def main(conn):
    # compute alice_seed
    alice_seed = get_seed(conn)
    print(alice_seed)

    # perform one iteration with arbitrary input to get a sample of values
    results = get_values(conn, b'BA==')
    bobnum = results[1]
    iv = results[2]
    ciphertext = results[3]

    # compute the encryption/decryption key
    alice = DiffieHellman(bit_flip(alice_seed))
    alice.set_other(bobnum)

    # decrypt the ciphertext
    cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
    plaintext = cipher.decrypt(ciphertext)
    print(plaintext)

if __name__ == '__main__':
    HOST = "127.0.0.1"
    PORT = 1337
    conn = remote(HOST, PORT)
    main(conn)
