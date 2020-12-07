Bit Flip 1
==========

Category: cryptography

Description
-----------

```
Flip bits and decrypt communication between Bob and Alice.

nc bitflip1.hackable.software 1337
```

When we unpack the attachment, we'll be given two files:

```
./flag
./task.py
```

The task.py contains the following code:

```python
#!/usr/bin/python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
import hashlib
import os
import base64
from gmpy2 import is_prime

FLAG = open("flag").read()
FLAG += (16 - (len(FLAG) % 16))*" "


class Rng:
  def __init__(self, seed):
    self.seed = seed
    self.generated = b""
    self.num = 0

  def more_bytes(self):
    self.generated += hashlib.sha256(self.seed).digest()
    self.seed = long_to_bytes(bytes_to_long(self.seed) + 1, 32)
    self.num += 256


  def getbits(self, num=64):
    while (self.num < num):
      self.more_bytes()
    x = bytes_to_long(self.generated)
    self.num -= num
    self.generated = b""
    if self.num > 0:
      self.generated = long_to_bytes(x >> num, self.num // 8)
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
  flip_str = base64.b64decode(input().strip())
  return xor32(flip_str, x)


alice_seed = os.urandom(16)

while 1:
  alice = DiffieHellman(bit_flip(alice_seed))
  bob = DiffieHellman(os.urandom(16), alice.prime)

  alice.set_other(bob.my_number)
  print("bob number", bob.my_number)
  bob.set_other(alice.my_number)
  iv = os.urandom(16)
  print(base64.b64encode(iv).decode())
  cipher = AES.new(long_to_bytes(alice.shared, 16)[:16], AES.MODE_CBC, IV=iv)
  enc_flag = cipher.encrypt(FLAG)
  print(base64.b64encode(enc_flag).decode())

```

Note that in order to run the task on our local computer, we can use socat like the following:

```
# socat tcp4-listen:1337,reuseaddr,fork exec:"python task.py"
```


Solution
--------

The important thing to note from the above is that ``alice_seed`` is computed once per program run and is afterwards not changed until we establish a new connection to the task and the task is respawned. If we look at the code we can see the input we provide to the program is XORed with ``alice_seed`` and then passed to the ``Rng`` random number generator as seed - this is the only input we control.

From the **seed** the random prime number is generated and the number of iterations is outputted to the stdout - this is where the vulnerability is, because that acts as a timing attack on the random number generation. Normally an attacker would need to measure the time it takes to generate a random number, but here the exact number of iterations it took to generate a random prime number is outputted. This is how we'll be able to derive the ``alice_seed`` and later decode the flag. Note also that the input we provide the program must be base64 encoded, because the program will base64 decode it first prior to using it.

The actual prime number is a 512-bits number, which is computed from concatenating two SHA256 hashes and is computed as follows and the number of iterations is outputted to stdout:

```
candidate = sha256(seed) + sha256(seed + 1)

iter = 0
while candidate not prime:
  candidate = sha256(seed + 2 + iter) + sha256(seed + 3 + iter)
  iter += 1
```

We know that ``alice_seed`` is a random number, but let's XOR that number with only a 1-bit input value: ``0b0`` and ``0b1``:

```
>>> import base64
>>> from Crypto.Util.number import bytes_to_long, long_to_bytes
>>> base64.b64encode(bytes(long_to_bytes(0b0)))
b'AA=='
>>> base64.b64encode(bytes(long_to_bytes(0b1)))
b'AQ=='
```

This gets us the following, where the number of iterations differ greatly, but the problem is that we cannot obtain the first bit.

.. figure:: first_bit.png

However what if we instead XOR ``alice_seed`` with a 2-bit input value, where we need to generate two values with the n-th bit set to 0 and 1, while the rest of the previous bits have already been identifier (we need to go in turn). This means we need to send in the value ``0b00`` and ``0b10`` and we get the following base64 values:

```
>>> base64.b64encode(bytes(long_to_bytes(0b00)))
b'AA=='
>>> base64.b64encode(bytes(long_to_bytes(0b10)))
b'Ag=='
```

When sending in these two values, we notice that the number of iterations has changed by exactly a single iteration.

.. figure:: second_bit.png

We can see than when the second bit is set, the input value will result in more iterations being required to get to the primer number. Let's see what this means by looking at the simple example where the ``alice_seed`` is an 8-bit random value ``0b10111010`` (decimal 186):

```
0b10111010 ^ 0b00 = 0b10111010 (186)
0b10111010 ^ 0b10 = 0b10111000 (184)
```

Therefore when the iterations are computed, they will be computed as follows, where the input value 0b00 will start with initial seed 186, while the input value 0b10 will start with initial seed 184 - this means we need one iteration more to get to the same 186 seed as the 0b00 has started with. This also means that the second bit of the ``alice_seed`` must be set to 1.


```
; for 0b00
candidate = sha256(186) + sha256(187)
candidate = sha256(188) + sha256(189)
candidate = sha256(190) + sha256(191)
candidate = sha256(192) + sha256(193)

; for 0x10
candidate = sha256(184) + sha256(185)
candidate = sha256(186) + sha256(187)
candidate = sha256(188) + sha256(189)
candidate = sha256(190) + sha256(191)
candidate = sha256(192) + sha256(193)
```

Let's do the same for the third bit.

```
>>> base64.b64encode(bytes(long_to_bytes(0b010)))
b'Ag=='
>>> base64.b64encode(bytes(long_to_bytes(0b110)))
b'Bg=='
```

If we sent it to the task, we can see that the number of iterations not differs by 2, but the 0b110 requires less number of iterations, so the actual value of the third bit is 0.

.. figure:: third_bit.png

Now the value of the seed is known to be 0b010, so we can continue with the forth bit.

```
>>> base64.b64encode(bytes(long_to_bytes(0b0010)))
b'Ag=='
>>> base64.b64encode(bytes(long_to_bytes(0b1010)))
b'Cg=='
```

Now the number of iterations differ by 4 and the 0b1010 requires more iterations, meaning the forth bit is set to 1.

.. figure:: forth_bit.png

We can continue with this approach manually, but we can see that the number of iterations does not differ by 1 all the time, but actually differs by the 2^(i-1), which is exactly the bit that is being set. Also this will work for the beginning LSB bits, but will not work for most of the bits, because as soon as we start computing values larger than 2**9, we'll start hitting the next prime number, not the prime that we're targetting. This means that we cannot use this approach for all of the bits, but let's see how we can modify our approach a little bit to be able to get all the bits.

What if we instead set an additiona bit to the already guessed seed, like we've done up until now. However instead of sending the orignal seed (with the current guessing bit set to 0), can we instead set all the bits expect the highest one to 1. Also we want the lowest bit set to 0, which is why we need to subtract 2 instead of 1 from the 2**i-1 value as we can see below.

```
>>> bin(2**5)
'0b100000'
>>> bin(2**5-1)
'0b11111'
>>> bin(2**5-2)
'0b11110'
```

We basically need to send the following values.

```
>>> seed = 0b11010
>>> bin(seed | 2**5)
'0b111010'
>>> bin(seed ^ (2**5-2))
'0b000100'
```

Keep in mind that we want to control the **seed** being passed to the Rng class, where the input is XORed with the actual value we pass in as input. Therefore if the current seed is ``0b11010``, the following values are passed as input to the Rng - we basically get exactly the values that we're after. This also implies the number of iterations s

```
>>> bin(seed ^ 0b111010)
'0b100000'
>>> bin(seed ^ 0b000100)
'0b11110'
```

Since the actual values are different by exactly 2, which is processes in a single iteration, it means that if the number if iterations between both number is different by exactly a single iteration, the bit is 0, otherwise it's 1. By using this logic we can quickly get to the following script that is capable of getting the ``alice_seed``:

```
#/usr/bin/env python
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
import base64
import struct

def get_num_iter(conn, value):
    # receive the bit-flip str:
    out = conn.recvline()

    # send the value
    conn.send(value + b'\n')

    # recv num iterations
    num_iter = str(conn.recvline())
    bob_num = conn.recvline()
    iv_num = conn.recvline()
    flag_num = conn.recvline()

    # return the actual number of iterations
    return int(num_iter.split(" ")[2:3][0])


def main():
    global HOST
    global PORT
    conn = remote(HOST, PORT)

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
        print("SOL:" + bin(sol)[2:])

if __name__ == '__main__':
    HOST = "127.0.0.1"
    PORT = 1337
    main()
```

If we run the above script, we will quickly reverse the value of the ``alice_seed``:

.. figure:: alice_seed.png

Afterwards, things are pretty straighforward and we can simply re-use both the ``Rng`` and ``DiffieHellman`` classes to perform the initialization of object ``alice`` through which the decryption key ``alice.shared`` is computed automatically - we don't need to do anything to get it except instantiate a ``DiffieHellman`` class with the previously computed seed.

Then we need to perform a single iteration of the task loop to obtain the bob secret number, the IV and the encrypted text and it's pretty straighforward to decrypt it to obtain the final solution. The final script that obtain the flag is the following:

```python
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
    print(conn.recvline())

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
```

The following shows an example of running the script and obtaining the flag:

.. code-block:: text

```
# python sol.py
[+] Opening connection to 127.0.0.1 on port 1337: Done
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AA==' [41], M: b'Ag==' [42]
SOL:       10
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AA==' [41], M: b'Bg==' [44]
SOL:       110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AA==' [41], M: b'Dg==' [48]
SOL:       1110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AA==' [41], M: b'Hg==' [40]
SOL:       1110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'EA==' [33], M: b'Lg==' [64]
SOL:       101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'EA==' [33], M: b'bg==' [32]
SOL:       101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'UA==' [1], M: b'rg==' [0]
SOL:       101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'0A==' [452], M: b'AS4=' [451]
SOL:       101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AdA=' [324], M: b'Ai4=' [64]
SOL:       1000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AdA=' [324], M: b'Bi4=' [277]
SOL:       11000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AdA=' [324], M: b'Di4=' [865]
SOL:       111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AdA=' [324], M: b'Hi4=' [62]
SOL:       1111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AdA=' [324], M: b'Pi4=' [315]
SOL:       11111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AdA=' [324], M: b'fi4=' [323]
SOL:       11111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'QdA=' [130], M: b'vi4=' [129]
SOL:       11111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'wdA=' [97], M: b'AT4u' [96]
SOL:       11111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AcHQ' [155], M: b'Aj4u' [433]
SOL:       100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AcHQ' [155], M: b'Bj4u' [154]
SOL:       100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BcHQ' [313], M: b'Cj4u' [26]
SOL:       10100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BcHQ' [313], M: b'Gj4u' [167]
SOL:       110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BcHQ' [313], M: b'Oj4u' [271]
SOL:       1110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BcHQ' [313], M: b'ej4u' [804]
SOL:       11110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BcHQ' [313], M: b'+j4u' [52]
SOL:       111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BcHQ' [313], M: b'Afo+Lg==' [589]
SOL:       1111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BcHQ' [313], M: b'A/o+Lg==' [907]
SOL:       11111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BcHQ' [313], M: b'B/o+Lg==' [101]
SOL:       111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BcHQ' [313], M: b'D/o+Lg==' [1009]
SOL:       1111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BcHQ' [313], M: b'H/o+Lg==' [312]
SOL:       1111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'EAXB0A==' [199], M: b'L/o+Lg==' [142]
SOL:       101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'EAXB0A==' [199], M: b'b/o+Lg==' [442]
SOL:       1101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'EAXB0A==' [199], M: b'7/o+Lg==' [198]
SOL:       1101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'kAXB0A==' [81], M: b'AW/6Pi4=' [80]
SOL:       1101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AZAFwdA=' [179], M: b'Am/6Pi4=' [977]
SOL:       1001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AZAFwdA=' [179], M: b'Bm/6Pi4=' [178]
SOL:       1001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BZAFwdA=' [506], M: b'Cm/6Pi4=' [505]
SOL:       1001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'DZAFwdA=' [114], M: b'Em/6Pi4=' [93]
SOL:       1001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'DZAFwdA=' [114], M: b'Mm/6Pi4=' [113]
SOL:       1001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'LZAFwdA=' [720], M: b'Um/6Pi4=' [719]
SOL:       1001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'bZAFwdA=' [99], M: b'km/6Pi4=' [178]
SOL:       1001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'bZAFwdA=' [99], M: b'AZJv+j4u' [98]
SOL:       1001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AW2QBcHQ' [413], M: b'ApJv+j4u' [84]
SOL:       101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AW2QBcHQ' [413], M: b'BpJv+j4u' [694]
SOL:       1101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AW2QBcHQ' [413], M: b'DpJv+j4u' [7]
SOL:       11101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AW2QBcHQ' [413], M: b'HpJv+j4u' [412]
SOL:       11101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'EW2QBcHQ' [210], M: b'LpJv+j4u' [57]
SOL:       1011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'EW2QBcHQ' [210], M: b'bpJv+j4u' [209]
SOL:       1011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'UW2QBcHQ' [157], M: b'rpJv+j4u' [156]
SOL:       1011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'0W2QBcHQ' [550], M: b'AS6Sb/o+Lg==' [549]
SOL:       1011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AdFtkAXB0A==' [105], M: b'Ai6Sb/o+Lg==' [104]
SOL:       1011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'A9FtkAXB0A==' [316], M: b'BC6Sb/o+Lg==' [540]
SOL:       100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'A9FtkAXB0A==' [316], M: b'DC6Sb/o+Lg==' [114]
SOL:       1100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'A9FtkAXB0A==' [316], M: b'HC6Sb/o+Lg==' [51]
SOL:       11100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'A9FtkAXB0A==' [316], M: b'PC6Sb/o+Lg==' [315]
SOL:       11100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'I9FtkAXB0A==' [583], M: b'XC6Sb/o+Lg==' [582]
SOL:       11100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'Y9FtkAXB0A==' [344], M: b'nC6Sb/o+Lg==' [343]
SOL:       11100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'49FtkAXB0A==' [55], M: b'ARwukm/6Pi4=' [54]
SOL:       11100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AePRbZAFwdA=' [839], M: b'Ahwukm/6Pi4=' [285]
SOL:       1000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AePRbZAFwdA=' [839], M: b'Bhwukm/6Pi4=' [838]
SOL:       1000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BePRbZAFwdA=' [840], M: b'Chwukm/6Pi4=' [322]
SOL:       101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BePRbZAFwdA=' [840], M: b'Ghwukm/6Pi4=' [97]
SOL:       1101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BePRbZAFwdA=' [840], M: b'Ohwukm/6Pi4=' [839]
SOL:       1101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'JePRbZAFwdA=' [451], M: b'Whwukm/6Pi4=' [1006]
SOL:       101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'JePRbZAFwdA=' [451], M: b'2hwukm/6Pi4=' [375]
SOL:       1101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'JePRbZAFwdA=' [451], M: b'AdocLpJv+j4u' [407]
SOL:       11101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'JePRbZAFwdA=' [451], M: b'A9ocLpJv+j4u' [450]
SOL:       11101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AiXj0W2QBcHQ' [37], M: b'BdocLpJv+j4u' [36]
SOL:       11101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BiXj0W2QBcHQ' [884], M: b'CdocLpJv+j4u' [340]
SOL:       10011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BiXj0W2QBcHQ' [884], M: b'GdocLpJv+j4u' [51]
SOL:       110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BiXj0W2QBcHQ' [884], M: b'OdocLpJv+j4u' [883]
SOL:       110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'JiXj0W2QBcHQ' [364], M: b'WdocLpJv+j4u' [363]
SOL:       110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'ZiXj0W2QBcHQ' [462], M: b'mdocLpJv+j4u' [461]
SOL:       110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'5iXj0W2QBcHQ' [284], M: b'ARnaHC6Sb/o+Lg==' [19]
SOL:       1000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'5iXj0W2QBcHQ' [284], M: b'AxnaHC6Sb/o+Lg==' [365]
SOL:       11000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'5iXj0W2QBcHQ' [284], M: b'BxnaHC6Sb/o+Lg==' [783]
SOL:       111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'5iXj0W2QBcHQ' [284], M: b'DxnaHC6Sb/o+Lg==' [283]
SOL:       111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'COYl49FtkAXB0A==' [672], M: b'FxnaHC6Sb/o+Lg==' [104]
SOL:       10111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'COYl49FtkAXB0A==' [672], M: b'NxnaHC6Sb/o+Lg==' [671]
SOL:       10111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'KOYl49FtkAXB0A==' [321], M: b'VxnaHC6Sb/o+Lg==' [320]
SOL:       10111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'aOYl49FtkAXB0A==' [297], M: b'lxnaHC6Sb/o+Lg==' [296]
SOL:       10111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'6OYl49FtkAXB0A==' [189], M: b'ARcZ2hwukm/6Pi4=' [81]
SOL:       100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'6OYl49FtkAXB0A==' [189], M: b'AxcZ2hwukm/6Pi4=' [186]
SOL:       1100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'6OYl49FtkAXB0A==' [189], M: b'BxcZ2hwukm/6Pi4=' [188]
SOL:       1100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BOjmJePRbZAFwdA=' [671], M: b'CxcZ2hwukm/6Pi4=' [65]
SOL:       101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BOjmJePRbZAFwdA=' [671], M: b'GxcZ2hwukm/6Pi4=' [670]
SOL:       101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'FOjmJePRbZAFwdA=' [1621], M: b'KxcZ2hwukm/6Pi4=' [1620]
SOL:       101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'NOjmJePRbZAFwdA=' [76], M: b'SxcZ2hwukm/6Pi4=' [312]
SOL:       100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'NOjmJePRbZAFwdA=' [76], M: b'yxcZ2hwukm/6Pi4=' [75]
SOL:       100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'tOjmJePRbZAFwdA=' [1615], M: b'AUsXGdocLpJv+j4u' [1614]
SOL:       100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AbTo5iXj0W2QBcHQ' [260], M: b'AksXGdocLpJv+j4u' [395]
SOL:       100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AbTo5iXj0W2QBcHQ' [260], M: b'BksXGdocLpJv+j4u' [259]
SOL:       100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BbTo5iXj0W2QBcHQ' [36], M: b'CksXGdocLpJv+j4u' [35]
SOL:       100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'DbTo5iXj0W2QBcHQ' [890], M: b'EksXGdocLpJv+j4u' [889]
SOL:       100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'HbTo5iXj0W2QBcHQ' [293], M: b'IksXGdocLpJv+j4u' [797]
SOL:       1000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'HbTo5iXj0W2QBcHQ' [293], M: b'YksXGdocLpJv+j4u' [292]
SOL:       1000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'XbTo5iXj0W2QBcHQ' [31], M: b'oksXGdocLpJv+j4u' [30]
SOL:       1000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'3bTo5iXj0W2QBcHQ' [126], M: b'ASJLFxnaHC6Sb/o+Lg==' [10]
SOL:       1001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'3bTo5iXj0W2QBcHQ' [126], M: b'AyJLFxnaHC6Sb/o+Lg==' [86]
SOL:       11001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'3bTo5iXj0W2QBcHQ' [126], M: b'ByJLFxnaHC6Sb/o+Lg==' [125]
SOL:       11001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BN206OYl49FtkAXB0A==' [100], M: b'CyJLFxnaHC6Sb/o+Lg==' [1198]
SOL:       1011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BN206OYl49FtkAXB0A==' [100], M: b'GyJLFxnaHC6Sb/o+Lg==' [99]
SOL:       1011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'FN206OYl49FtkAXB0A==' [10], M: b'KyJLFxnaHC6Sb/o+Lg==' [238]
SOL:       101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'FN206OYl49FtkAXB0A==' [10], M: b'ayJLFxnaHC6Sb/o+Lg==' [11]
SOL:       1101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'FN206OYl49FtkAXB0A==' [10], M: b'6yJLFxnaHC6Sb/o+Lg==' [172]
SOL:       11101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'FN206OYl49FtkAXB0A==' [10], M: b'AesiSxcZ2hwukm/6Pi4=' [138]
SOL:       111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'FN206OYl49FtkAXB0A==' [10], M: b'A+siSxcZ2hwukm/6Pi4=' [9]
SOL:       111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AhTdtOjmJePRbZAFwdA=' [29], M: b'BesiSxcZ2hwukm/6Pi4=' [974]
SOL:       10111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AhTdtOjmJePRbZAFwdA=' [29], M: b'DesiSxcZ2hwukm/6Pi4=' [28]
SOL:       10111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'ChTdtOjmJePRbZAFwdA=' [61], M: b'FesiSxcZ2hwukm/6Pi4=' [60]
SOL:       10111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'GhTdtOjmJePRbZAFwdA=' [324], M: b'JesiSxcZ2hwukm/6Pi4=' [323]
SOL:       10111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'OhTdtOjmJePRbZAFwdA=' [705], M: b'ResiSxcZ2hwukm/6Pi4=' [99]
SOL:       100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'OhTdtOjmJePRbZAFwdA=' [705], M: b'xesiSxcZ2hwukm/6Pi4=' [107]
SOL:       1100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'OhTdtOjmJePRbZAFwdA=' [705], M: b'AcXrIksXGdocLpJv+j4u' [319]
SOL:       11100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'OhTdtOjmJePRbZAFwdA=' [705], M: b'A8XrIksXGdocLpJv+j4u' [704]
SOL:       11100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AjoU3bTo5iXj0W2QBcHQ' [114], M: b'BcXrIksXGdocLpJv+j4u' [113]
SOL:       11100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BjoU3bTo5iXj0W2QBcHQ' [47], M: b'CcXrIksXGdocLpJv+j4u' [762]
SOL:       10011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'BjoU3bTo5iXj0W2QBcHQ' [47], M: b'GcXrIksXGdocLpJv+j4u' [46]
SOL:       10011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'FjoU3bTo5iXj0W2QBcHQ' [223], M: b'KcXrIksXGdocLpJv+j4u' [222]
SOL:       10011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'NjoU3bTo5iXj0W2QBcHQ' [539], M: b'ScXrIksXGdocLpJv+j4u' [538]
SOL:       10011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'djoU3bTo5iXj0W2QBcHQ' [201], M: b'icXrIksXGdocLpJv+j4u' [24]
SOL:       100010011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'djoU3bTo5iXj0W2QBcHQ' [201], M: b'AYnF6yJLFxnaHC6Sb/o+Lg==' [200]
SOL:       100010011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'AXY6FN206OYl49FtkAXB0A==' [182], M: b'AonF6yJLFxnaHC6Sb/o+Lg==' [181]
SOL:       100010011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'A3Y6FN206OYl49FtkAXB0A==' [183], M: b'BInF6yJLFxnaHC6Sb/o+Lg==' [263]
SOL:       100100010011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'A3Y6FN206OYl49FtkAXB0A==' [183], M: b'DInF6yJLFxnaHC6Sb/o+Lg==' [182]
SOL:       100100010011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'C3Y6FN206OYl49FtkAXB0A==' [313], M: b'FInF6yJLFxnaHC6Sb/o+Lg==' [312]
SOL:       100100010011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'G3Y6FN206OYl49FtkAXB0A==' [773], M: b'JInF6yJLFxnaHC6Sb/o+Lg==' [19]
SOL:       100100100010011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'G3Y6FN206OYl49FtkAXB0A==' [773], M: b'ZInF6yJLFxnaHC6Sb/o+Lg==' [399]
SOL:       1100100100010011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'bit-flip str:\n'
b'bit-flip str:\n'
N: b'G3Y6FN206OYl49FtkAXB0A==' [773], M: b'5InF6yJLFxnaHC6Sb/o+Lg==' [83]
SOL:       11100100100010011100010111101011001000100100101100010111000110011101101000011100001011101001001001101111111110100011111000101110
b'\xe4\x89\xc5\xeb"K\x17\x19\xda\x1c.\x92o\xfa>.'
b'bit-flip str:\n'
bit-flip str:
Generated after 43 iterations
b'DrgnS{T1min9_4ttack_f0r_k3y_generation}\n        '
```

