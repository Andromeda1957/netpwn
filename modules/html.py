#!/usr/bin/python
"""Html Convert."""

import HTMLParser
import cgi

from termcolor import colored


def convert():
    """Escape and unescape html characters."""
    print colored('Enter a string to html encode or decode', 'green')
    input_str = raw_input(colored('(netpwn: html_converter) > ', 'red'))
    encoded = cgi.escape(input_str)
    decoded = HTMLParser.HTMLParser().unescape(input_str)
    print colored('Encoded: ' + encoded, 'green')
    print colored('Decoded: ' + decoded, 'green')
