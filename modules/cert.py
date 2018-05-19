#!/usr/bin/python
"""ssl module."""

import socket
import ssl

from termcolor import colored


def ssl_cert():
    """Get the ssl cert of a website."""
    print colored('Enter a URL to get its SSL cert', 'green')
    target_url = raw_input(colored('(netpwn: ssl_cert) > ', 'red'))

    try:
        cert = ssl.get_server_certificate((target_url, 443))
        ctx = ssl.create_default_context()
        socks = socket.socket()
        sock = ctx.wrap_socket(socks, server_hostname=target_url)
        sock.connect((target_url, 443))
        certs = sock.getpeercert()
        subject = dict(x[0] for x in certs['subject'])
        country = subject['countryName']
        issued_to = subject['commonName']
        organization = subject['organizationName']
        location = subject['stateOrProvinceName']
        issuer = dict(x[0] for x in certs['issuer'])
        issued_by = issuer['commonName']
        print colored(cert, 'green')
        print colored('Country: ' + country, 'green')
        print colored('Issued to: ' + issued_to, 'green')
        print colored('Organization: ' + organization, 'green')
        print colored('Province: ' + location, 'green')
        print colored('Issued by: ' + issued_by, 'green')
        print ' '

    except socket.error:
        print colored('Unknown host: ' + target_url, 'yellow')

    except KeyError:
        print colored('No SSL cert', 'yellow')
