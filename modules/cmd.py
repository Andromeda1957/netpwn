#!/usr/bin/python
"""bash module"""

import os

from termcolor import colored


def bash():
    """Run bash"""
    print colored('Type [back] to return to netpwn', 'green')

    while True:
        command = raw_input(colored('(netpwn: bash) > ', 'red'))

        if command == 'back':
            break

        else:
            os.system(command)
