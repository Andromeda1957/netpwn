#!/usr/bin/python
"""Rot13."""

import codecs

from termcolor import colored


def convert():
    """Convert to or from Rot13."""
    print colored('Enter text to encode or decode as rot13', 'green')
    input_str = raw_input(colored('(netpwn: rot13_converter) > ', 'red'))
    output = codecs.encode(input_str, 'rot_13')
    print colored(output, 'green')
