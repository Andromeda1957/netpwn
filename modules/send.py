#!/usr/bin/python
"""send module."""

import socket

from termcolor import colored


def send_file():
    """Send file to remote location."""
    try:
        print colored('Enter the IP to send file to', 'green')
        address = raw_input(colored('(netpwn: send_file) > ', 'red'))
        print colored('Enter the port to send file to', 'green')
        port = int(raw_input(colored('(netpwn: send_file) > ', 'red')))
        print colored('Enter directory of file to send', 'green')
        input_file = raw_input(colored('(netpwn: send_file) > ', 'red'))
        open_file = open(input_file)
        send = open_file.read()
        transfer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        transfer.connect((address, port))
        transfer.send(send)

    except ValueError as error:
        print colored('Could not send file to ' + str(error), 'yellow')

    except IOError as error:
        print colored('Could not find ' + str(error), 'yellow')
