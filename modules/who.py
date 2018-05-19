#!/usr/bin/python
"""whois module."""

from termcolor import colored
from whois import whois


def whois_lookup():
    """Perform whois."""
    try:
        print colored('Enter a URL to get whois data', 'green')
        domain = raw_input(colored('(netpwn: whois) > ', 'red'))
        target = [domain]
        targets = whois(target[0])
        print colored('name: ' + targets['name'], 'green')
        print colored('city: ' + targets['city'], 'green')
        print colored('zipcode: ' + targets['zipcode'], 'green')
        print colored('country: ' + targets['country'], 'green')
        print colored('state: ' + targets['state'], 'green')
        print colored('registrar: ' + targets['registrar'], 'green')
        print colored('address : ' + targets['address'], 'green')
        print colored('org : ' + targets['org'], 'green')

        for domains in targets['domain_name']:
            print colored('DNS: ' + domains, 'green')

        for emails in targets['emails']:
            print colored('emails : ' + emails, 'green')

    except TypeError:
        print colored('Cannot retrieve information', 'red')
