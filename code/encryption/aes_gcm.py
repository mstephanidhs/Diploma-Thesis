#!/usr/bin/env python

"""
    Copyright (C) 2013 Bo Zhu http://about.bozhu.me

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
"""

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.number import long_to_bytes, bytes_to_long


# used to perform multiplication in the Galois Field GF(2^128), which is used in
# the AES-GCM algorithm for generating authentication tags.
# GF(2^128) defined by 1 + a + a^2 + a^7 + a^128
# Please note the MSB is x0 and LSB is x127
def gf_2_128_mul(x, y):
    # check that both x and y are less than 2^128, ensuring that they are valid inputs
    # for multiplication in this finite field.
    assert x < (1 << 128)
    assert y < (1 << 128)

    # store the result of the multiplication.
    res = 0

    # iterate over each bit position of the binary representation of
    # y, starting from the most significant bit (MSB) and moving towards
    # the least significant bit (LSB).
    for i in range(127, -1, -1):
        # performs the actual multiplication of x and the i-th bit of y. It uses
        # bitwise operations to access and extract the i-th bit of y and then multiplies
        # it by x.
        # The ^ operator is used for bitwise XOR, so the result
        # of each multiplication is XORed with the accumulated result res.
        res ^= x * ((y >> i) & 1)  # branchless

        # It is right-shifted by one bit (equivalent to dividing by 2), and then a conditional XOR
        # operation is applied based on the least significant bit (LSB) of x. This conditional XOR
        # is a branchless operation that applies a specific polynomial if the LSB of x is 1.
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)

    # asserts that the result res is still less than 2^128, ensuring that the multiplication result
    # remains within the finite field.
    assert res < 1 << 128
    return res


# raised when there is invalid input to the AES-GCM operations.
class InvalidInputException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)

# raised when the authentication tag is invalid.


class InvalidTagException(Exception):
    def __str__(self):
        return 'The authenticaiton tag is invalid.'


# Galois/Counter Mode with AES-128 and 96-bit IV
class AES_GCM:
    def __init__(self, master_key):
        self.change_key(master_key)

    def change_key(self, master_key):
        if master_key >= (1 << 128):
            raise InvalidInputException('Master key should be 128-bit')

        # It converts the master_key from an integer to a 16-byte byte string. This is the key that will
        # be used for encryption and authentication.
        self.__master_key = long_to_bytes(master_key, 16)

        self.__aes_ecb = AES.new(self.__master_key, AES.MODE_ECB)

        # It encrypts a 16-byte block of all zeros (b'\x00' * 16) using the ECB cipher self.__aes_ecb and
        # converts the result to a long integer using bytes_to_long. This is the authentication key used for
        # the GHASH operation in AES-GCM.
        self.__auth_key = bytes_to_long(self.__aes_ecb.encrypt(b'\x00' * 16))

        # precompute the table for multiplication in finite field
        table = []  # for 8-bit
        for i in range(16):
            row = []
            for j in range(256):
                # iterates over all 256 possible byte values (0-255) and computes the result of multiplying the
                # authentication key by j << (8 * i) using the gf_2_128_mul function. This result is appended to the row.
                row.append(gf_2_128_mul(self.__auth_key, j << (8 * i)))

            # Each row of results is converted into a tuple and added to the table. This table stores precomputed values
            # for the GHASH operation, which is used for authentication in AES-GCM.
            table.append(tuple(row))
        self.__pre_table = tuple(table)

        self.prev_init_value = None  # reset

    # responsible for performing the multiplication of a value val with the authentication key in the finite field GF(2^128).
    def __times_auth_key(self, val):
        # store the result of the multiplication.
        res = 0
        for i in range(16):
            # performs the multiplication for one byte at a time. It takes the least significant byte of val by applying a bitwise
            # AND operation with 0xFF. This extracts the lowest 8 bits of val.
            # It then uses these 8 bits as an index into the precomputed table self.__pre_table. This retrieves a value from the table, which represents the product of the authentication key and the 8-bit value.
            # The result res is XORed with this value. XOR is used because it corresponds to addition in the finite field.
            res ^= self.__pre_table[i][val & 0xFF]

            # is right-shifted by 8 bits, effectively discarding the least significant byte. This prepares val for the next iteration to
            # process the next byte.
            val >>= 8

        return res

    def __ghash(self, aad, txt):
        # aad (the associated data)
        len_aad = len(aad)
        # txt (the plaintext or ciphertext)
        len_txt = len(txt)

        # padding
        # If the length of aad is already a multiple of 16, it leaves data as aad. Otherwise, it appends zero bytes (b'\x00')
        # to aad to make its length a multiple of 16.
        if 0 == len_aad % 16:
            data = aad
        else:
            data = aad + b'\x00' * (16 - len_aad % 16)

        # ensures it is also a multiple of 16 bytes. It appends zero bytes as needed to make the length of data a multiple of 16.
        if 0 == len_txt % 16:
            data += txt
        else:
            data += txt + b'\x00' * (16 - len_txt % 16)

        tag = 0
        assert len(data) % 16 == 0

        # This loop iterates over the blocks of data (each block is 16 bytes) and performs the GHASH operation. It XORs the
        # 128-bit block (converted to a long integer using bytes_to_long) with the current value of tag, and then it updates
        # tag by calling the __times_auth_key method, effectively performing finite field multiplication.
        for i in range(len(data) // 16):
            tag ^= bytes_to_long(data[i * 16: (i + 1) * 16])
            tag = self.__times_auth_key(tag)
            # print 'X\t', hex(tag)

        # After processing all blocks, it XORs the result with a 128-bit value derived from the lengths of the associated data
        # and plaintext/ciphertext. This step is part of the GHASH calculation.
        tag ^= ((8 * len_aad) << 64) | (8 * len_txt)
        tag = self.__times_auth_key(tag)

        return tag

    def encrypt(self, init_value, plaintext, auth_data=b''):
        if init_value >= (1 << 96):
            raise InvalidInputException('IV should be 96-bit')
        # a naive checking for IV reuse
        if init_value == self.prev_init_value:
            raise InvalidInputException('IV must not be reused!')
        self.prev_init_value = init_value

        len_plaintext = len(plaintext)
        # len_auth_data = len(auth_data)

        if len_plaintext > 0:
            counter = Counter.new(
                nbits=32,
                prefix=long_to_bytes(init_value, 12),
                initial_value=2,  # notice this
                allow_wraparound=False)
            aes_ctr = AES.new(self.__master_key, AES.MODE_CTR, counter=counter)

            # ensures that the plaintext is a multiple of 16 bytes (128 bits) by padding it with zero bytes if necessary.
            # If the length of plaintext is not a multiple of 16, it appends the required number of zero bytes to make
            # it a multiple of 16.
            if 0 != len_plaintext % 16:
                padded_plaintext = plaintext + \
                    b'\x00' * (16 - len_plaintext % 16)
            else:
                padded_plaintext = plaintext

            # It encrypts the padded plaintext using AES-CTR mode and stores the result in the ciphertext variable.
            # The [:len_plaintext] slice is used to ensure that the ciphertext has the same length as the original plaintext.
            ciphertext = aes_ctr.encrypt(padded_plaintext)[:len_plaintext]

        else:
            ciphertext = b''

        # It calculates the authentication tag (auth_tag) by calling the __ghash method with the associated data (auth_data)
        # and the ciphertext as inputs. This computes the GHASH operation, which is used for authentication in AES-GCM.
        auth_tag = self.__ghash(auth_data, ciphertext)
        # print 'GHASH\t', hex(auth_tag)
        auth_tag ^= bytes_to_long(self.__aes_ecb.encrypt(
                                  long_to_bytes((init_value << 32) | 1, 16)))

        # assert len(ciphertext) == len(plaintext)
        assert auth_tag < (1 << 128)
        return ciphertext, auth_tag

    def decrypt(self, init_value, ciphertext, auth_tag, auth_data=b''):
        if init_value >= (1 << 96):
            raise InvalidInputException('IV should be 96-bit')
        if auth_tag >= (1 << 128):
            raise InvalidInputException('Tag should be 128-bit')

        # This block of code verifies the authenticity of the ciphertext and associated data by comparing the provided
        # auth_tag with a newly computed authentication tag. It first calculates the GHASH result for the associated
        # data and ciphertext using the __ghash method.
        # It then calculates the expected authentication tag by encrypting a 16-byte block created from the init_value
        # left-shifted by 32 bits and ORed with 1, using the AES ECB mode. This step is part of the GHASH calculation.
        # If the provided auth_tag does not match the calculated authentication tag, it raises an InvalidTagException,
        # indicating that the data or tag has been tampered with
        if auth_tag != self.__ghash(auth_data, ciphertext) ^ \
                bytes_to_long(self.__aes_ecb.encrypt(
                long_to_bytes((init_value << 32) | 1, 16))):
            raise InvalidTagException

        len_ciphertext = len(ciphertext)
        if len_ciphertext > 0:
            counter = Counter.new(
                nbits=32,
                prefix=long_to_bytes(init_value, 12),
                initial_value=2,
                allow_wraparound=True)
            aes_ctr = AES.new(self.__master_key, AES.MODE_CTR, counter=counter)

            if 0 != len_ciphertext % 16:
                padded_ciphertext = ciphertext + \
                    b'\x00' * (16 - len_ciphertext % 16)
            else:
                padded_ciphertext = ciphertext
            plaintext = aes_ctr.decrypt(padded_ciphertext)[:len_ciphertext]

        else:
            plaintext = b''

        return plaintext


if __name__ == '__main__':
    master_key = 0xfeffe9928665731c6d6a8f9467308308
    plaintext = b'\xd9\x31\x32\x25\xf8\x84\x06\xe5' + \
                b'\xa5\x59\x09\xc5\xaf\xf5\x26\x9a' + \
                b'\x86\xa7\xa9\x53\x15\x34\xf7\xda' + \
                b'\x2e\x4c\x30\x3d\x8a\x31\x8a\x72' + \
                b'\x1c\x3c\x0c\x95\x95\x68\x09\x53' + \
                b'\x2f\xcf\x0e\x24\x49\xa6\xb5\x25' + \
                b'\xb1\x6a\xed\xf5\xaa\x0d\xe6\x57' + \
                b'\xba\x63\x7b\x39'
    auth_data = b'\xfe\xed\xfa\xce\xde\xad\xbe\xef' + \
                b'\xfe\xed\xfa\xce\xde\xad\xbe\xef' + \
                b'\xab\xad\xda\xd2'
    init_value = 0xcafebabefacedbaddecaf888
    ciphertext = b'\x42\x83\x1e\xc2\x21\x77\x74\x24' + \
                 b'\x4b\x72\x21\xb7\x84\xd0\xd4\x9c' + \
                 b'\xe3\xaa\x21\x2f\x2c\x02\xa4\xe0' + \
                 b'\x35\xc1\x7e\x23\x29\xac\xa1\x2e' + \
                 b'\x21\xd5\x14\xb2\x54\x66\x93\x1c' + \
                 b'\x7d\x8f\x6a\x5a\xac\x84\xaa\x05' + \
                 b'\x1b\xa3\x0b\x39\x6a\x0a\xac\x97' + \
                 b'\x3d\x58\xe0\x91'
    auth_tag = 0x5bc94fbc3221a5db94fae95ae7121a47

    print('plaintext:', hex(bytes_to_long(plaintext)))

    my_gcm = AES_GCM(master_key)
    encrypted, new_tag = my_gcm.encrypt(init_value, plaintext, auth_data)
    print('encrypted:', hex(bytes_to_long(encrypted)))
    print('auth tag: ', hex(new_tag))

    try:
        decrypted = my_gcm.decrypt(init_value, encrypted,
                                   new_tag + 1, auth_data)
    except InvalidTagException:
        decrypted = my_gcm.decrypt(init_value, encrypted, new_tag, auth_data)
        print('decrypted:', hex(bytes_to_long(decrypted)))
