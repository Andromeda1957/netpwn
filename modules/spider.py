#!/usr/bin/python
"""spider module"""

import re
from urllib2 import urlopen

from termcolor import colored


def web_spider():
    """Web spider"""
    try:
        print colored('Enter a URL to crawl', 'green')
        target_url = raw_input(colored('(netpwn: web_spider) > ', 'red'))
        pattern = '''href=["'](.[^"']+)["']'''

        for urls in re.findall(pattern, urlopen(target_url).read(), re.I):
            print colored(urls, 'green')

    except ValueError:
        print colored('Cannot crawl URL', 'yellow')
