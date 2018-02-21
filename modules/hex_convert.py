#!/usr/bin/python
"""hex converter module"""

from termcolor import colored


def hex_converter():
    """Converts to and from hexadecimal"""
    print colored('This converts hex to ascii and ascii to hex')
    input_str = raw_input(colored('(netpwn: hex_converter) > ', 'red'))
    decoded = input_str
    encoded = input_str

    try:
        if any(i in decoded for i in '0x'):
            decoded = decoded.replace('0x', '')

        if any(i in decoded for i in '\\x'):
            decoded = decoded.replace('\\x', '')

        decoded = decoded.decode('hex')
        print colored('Decoded as: ' + decoded, 'green')

    except TypeError:
        print colored('No hex value was given to decode', 'yellow')

    encoded = encoded.encode('hex')
    print colored('Encoded as: ' + '0x' + encoded)
