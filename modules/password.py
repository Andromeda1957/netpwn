#!/usr/bin/python
"""password checking module"""

import re

from termcolor import colored


def password_checker():
    """Checks password strength"""
    print colored('Enter a password to check', 'green')
    password = raw_input(colored('(netpwn: password_checker) > ', 'red'))
    length = len(password)

    if length < 12:
        print colored('Your password is too short ', 'yellow')

    else:
        print colored('Good password length', 'green')

    if password.isupper() is False and password.islower() is False:
        print colored('Good password case mixture', 'green')

    else:
        print colored('Bad password case mixture', 'yellow')

    if re.match('^[a-zA-Z0-9_]*$', password):
        print colored('Does not contain special chararacters', 'yellow')

    else:
        print colored('Does contain special chararacters', 'green')

    def check_for_nums(password):
        """Checks password for numbers"""
        return any(i.isdigit() for i in password)

    if check_for_nums(password) is False:
        print colored('Your password does not contain any numbers', 'yellow')

    else:
        print colored('Your password contains numbers', 'green')
