#!/usr/bin/python
"""Base64 module."""

import base64

from termcolor import colored


def base64_converter():
    """Convert to and from base64."""
    print colored('Enter some text to encode or decode as base64', 'green')
    print colored('This will automatically try to encode or decode', 'green')
    input_str = raw_input(colored('(netpwn: base64_converter) > ', 'red'))

    try:
        output = base64.b64decode(input_str)
        output.encode('ascii')

    except TypeError:
        output = base64.b64encode(input_str)

    print colored(output, 'green')
