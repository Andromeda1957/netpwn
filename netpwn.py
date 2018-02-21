#!/usr/bin/python
"""netpwn pentesting tool"""
# Created by 3XPL017
# Member of @togetherwehack

import readline
import os
import sys
from termcolor import colored
from modules import *

OPTIONS_SL = [
    'reverse_shell',
    'send_file',
    'php_backdoor',
    'hash_check',
    'base64_converter',
    'address_info',
    'generate_shellcode',
    'hex_converter',
    'page_contents',
    'password_checker',
    'fake_identity',
    'web_spider',
    'ssl_cert',
    'bash',
    'whois',
    'help',
    'modules'
    ]

TABCOMP = OPTIONS_SL


def completer(text, state):
    """Tab complete"""
    options = [x for x in TABCOMP if x.startswith(text)]

    try:
        return options[state]

    except IndexError:
        return None


readline.set_completer(completer)
readline.parse_and_bind("tab: complete")


def check_root():
    """Checks for root privileges"""
    if not os.geteuid() == 0 and not os.getgid() == 0:
        return False


def banner():
    """Displays the netpwn banner"""
    print colored(r'               __                       ', 'blue')
    print colored(r'  ____   _____/  |_________  _  ______  ', 'blue')
    print colored(r' /    \_/ __ \   __\____ \ \/ \/ /    \ ', 'blue')
    print colored(r'|   |  \  ___/|  | |  |_> >     /   |  \ ', 'blue')
    print colored(r'|___|  /\___  >__| |   __/ \/\_/|___|  /', 'blue')
    print colored(r'     \/     \/     |__|              \/ ', 'blue')
    print ' '
    print colored(r'     | Created by 3XPL017         |', 'blue')
    print colored(r'     | twitter: @3XPL017GH057     |', 'blue')
    print colored(r'     | https://github.com/3XPL017 |', 'blue')
    print ' '
    print colored(r'         15 modules loaded', 'green')
    print '\n' * 9


def modules():
    """Prints available modules"""
    print ' '
    print colored('Modules', 'green')
    print colored('=======', 'green')
    print colored('reverse_shell', 'green')
    print colored('send_file', 'green')
    print colored('php_backdoor', 'green')
    print colored('hash_check', 'green')
    print colored('base64_converter', 'green')
    print colored('address_info', 'green')
    print colored('generate_shellcode', 'green')
    print colored('hex_converter', 'green')
    print colored('page_contents', 'green')
    print colored('password_checker', 'green')
    print colored('fake_identity', 'green')
    print colored('web_spider', 'green')
    print colored('ssl_cert', 'green')
    print colored('bash', 'green')
    print colored('whois', 'green')
    print ' '


def help_menu():
    """Prints help menu"""
    print ' '
    print colored('Commands', 'green')
    print colored('========', 'green')
    print colored(
        'modules        lists available modules', 'green')
    print colored(
        'banner         displays the banner', 'green')
    print colored(
        'clear          clears the screen', 'green')
    print colored(
        'exit           exits netpwn', 'green')
    print ' '


def main():
    """Handles which function to run"""
    if check_root() is False:
        sys.exit(colored('netpwn must be run as root', 'yellow'))

    choice = raw_input(colored('(netpwn) > ', 'red'))

    options = {
        'reverse_shell': reverse.reverse_shell,
        'send_file': send.send_file,
        'php_backdoor': backdoor.php_backdoor,
        'hash_check': hasher.hash_check,
        'base64_converter': base64_convert.base64_converter,
        'address_info': address.address_info,
        'generate_shellcode': shellcode.generate_shellcode,
        'hex_converter': hex_convert.hex_converter,
        'page_contents': page.page_contents,
        'password_checker': password.password_checker,
        'fake_identity': identity.fake_identity,
        'web_spider': spider.web_spider,
        'ssl_cert': cert.ssl_cert,
        'bash': cmd.bash,
        'whois': who.whois_lookup,
        'help': help_menu,
        'modules': modules,
        'clear': lambda: os.system('clear'),
        'banner': banner,
        'exit': lambda: exit(0),
        '': lambda: 1 + 1
    }

    if choice not in options:
        print colored('Unknown command: ' + choice, 'yellow')

    options.get(choice, lambda: None)()
    main()


if __name__ == '__main__':
    check_root()
    banner()
    main()
