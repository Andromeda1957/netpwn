#!/usr/bin/python
"""No endian."""

from termcolor import colored


def no_little():
    """Remove little endian."""
    print colored('Enter a DWORD(4 bytes) of hex data', 'green')
    input_str = raw_input(colored('(netpwn: no_endian) > ', 'red'))
    dword = input_str.strip('0x')
    byte = dword[6:8]
    byte1 = dword[4:6]
    byte2 = dword[2:4]
    byte3 = dword[0:2]
    new_dword = byte + byte1 + byte2 + byte3

    try:
        print colored("New DWORD: 0x" + new_dword, 'green')
        print colored(new_dword.decode('hex'), 'green')

    except TypeError:
        print colored('Please enter a DWORD', 'yellow')
