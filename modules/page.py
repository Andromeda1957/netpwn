#!/usr/bin/python
"""get page contents module"""

from urllib2 import urlopen
from termcolor import colored


def page_contents():
    """Shows contents of a web page"""
    try:
        print colored('Enter URL', 'green')
        target_url = raw_input(colored('(netpwn: page_contents) > ', 'red'))
        contents = urlopen(target_url).read()
        save = raw_input(colored('Save to file: ', 'green'))

        if save == 'yes' or save == 'y':
            print colored('Saved to page.txt', 'green')
            save_file = open('page.txt', 'w')
            save_file.write(contents)

        else:
            print colored(contents, 'green')

    except ValueError as error:
        print colored('Not a valid URL ' + str(error), 'yellow')
