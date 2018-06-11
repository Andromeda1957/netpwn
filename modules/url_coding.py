#!/usr/bin/python
"""URL encode and decode."""

import urllib

from termcolor import colored


def converting():
    """Convert to and from."""
    print colored('Enter a string to encode or decode', 'green')
    input_str = raw_input(colored('(netpwn: url_converter) > ', 'red'))
    encode = urllib.quote_plus(input_str).encode('utf8')
    decode = urllib.unquote(input_str).decode('utf8')
    print colored('Encoded: ' + encode, 'green')
    print colored('Decoded: ' + decode, 'green')
