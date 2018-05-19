#!/usr/bin/python
"""address info module"""

import fcntl
import socket
import struct
from urllib2 import urlopen

import netifaces

from termcolor import colored


def address_info():
    """Gets networking information"""
    print colored('Enter interface', 'green')
    interface = raw_input(colored('(netpwn: address_info) > ', 'red'))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        val = struct.pack('256s', interface[:15])
        info = fcntl.ioctl(sock.fileno(), 0x8927, val)
        joining = ['%02x' % ord(char) for char in info[18:24]]
        print colored('Your MAC is: ' + ':'.join(joining), 'green')

    except IOError as error:
        print colored('Invalid interface ' + str(error), 'yellow')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(('8.8.8.8', 80))
    print colored('Your ipv4 is : ' + (sock.getsockname()[0]), 'green')
    sock.close()

    try:
        addrs = netifaces.ifaddresses(interface)
        address6 = addrs[netifaces.AF_INET6][0]['addr']
        address6_1 = addrs[netifaces.AF_INET6][1]['addr']
        address6_2 = addrs[netifaces.AF_INET6][2]['addr']
        print colored('Your ipv6 is: ' + address6, 'green')
        print colored('Your ipv6 is: ' + address6_1, 'green')
        print colored('Your ipv6 is: ' + address6_2, 'green')

    except ValueError as error:
        print colored('Invalid interface ' + str(error), 'yellow')

    my_gateway = netifaces.gateways()
    getgateway = my_gateway['default'][socket.AF_INET][0]
    print colored('Your default gateway is: ' + getgateway, 'green')
    my_ip = urlopen('http://ipinfo.io/ip').read()
    print colored('Your public IP is: ' + my_ip, 'green')
