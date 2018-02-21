#!/usr/bin/python
"""hash check module"""

from termcolor import colored


def hash_check():
    """Detects input hash type"""
    print colored('Enter a hash to determine its type', 'green')
    input_hash = raw_input(colored('(netwn: hash_check) > ', 'red'))

    if len(input_hash) == 32:
        print colored('Hash type: md5', 'green')

    elif len(input_hash) == 40:
        print colored('Hash type: sha1', 'green')

    elif len(input_hash) == 64:
        print colored('Hash type: sha256', 'green')

    elif len(input_hash) == 128:
        print colored('Hash type: sha512', 'green')

    else:
        print colored('No hash type found', 'green')
