#!/usr/bin/python
"""Encrypt and decrypt files."""

import os

from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Protocol.KDF import PBKDF2

from termcolor import colored


def crypt():
    """Encrypt and decrypt a file."""
    print colored('Enter 1 to encrypt 2 to decrypt', 'green')
    choice = raw_input(colored('(netpwn: crypto) > ', 'red'))

    if not (choice == '1' or choice == '2'):
        error = 'Not a valid choice'
        print colored(error, 'yellow')
        return error

    print colored('Enter your input file', 'green')
    file = raw_input(colored('(netpwn: crypto) > ', 'red'))
    print colored('Enter a password to encrypt or decrypt with', 'green')

    key = raw_input(colored('(netpwn: crypto) > ', 'red'))

    try:
        inputfile = open(file, 'rb')
    except IOError:
        print colored('Could not open file', 'yellow')

    salt = "data"
    kdf = PBKDF2(key, salt, 64, 1000)
    key = kdf[:32]
    key_mac = kdf[32:]
    mac = HMAC.new(key_mac)

    if choice == '1':
        try:
            print colored('Saving as encrypted.txt', 'green')
            output = open('encrypted.txt', 'wb')
        except IOError:
            print colored('Could not create the output file', 'yellow')

        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        encrypted = cipher.encrypt(inputfile.read())
        mac.update(iv + encrypted)
        output.write(mac.hexdigest())
        output.write(iv)
        output.write(encrypted)
        print colored(encrypted, 'green')

    elif choice == '2':
        try:
            print colored('Saving as decrypted.txt', 'green')
            output = open('decrypted.txt', 'wb')
        except IOError:
            print colored('Could not create the output file', 'yellow')

        data = inputfile.read()
        verify = data[0:32]
        mac.update(data[32:])

        if mac.hexdigest() != verify:
            print colored('Wrong password', 'yellow')

        iv = data[32:48]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        decrypted = cipher.decrypt(data[48:])
        output.write(decrypted)
        print colored(decrypted, 'green')
