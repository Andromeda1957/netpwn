#!/usr/bin/python
"""netpwn pentesting tool."""
# Created by 3XPL017
# Member of @togetherwehack

import os
import readline
import sys

from modules import address
from modules import backdoor
from modules import base64_convert
from modules import cert
from modules import cmd
from modules import crypto
from modules import hasher
from modules import hex_convert
from modules import identity
from modules import no_endian
from modules import page
from modules import password
from modules import reverse
from modules import send
from modules import spider
from modules import who

from resources import cheat_sheet
from resources import links
from resources import opcodes

from termcolor import colored


OPTIONS_SL = [
    'reverse_shell',
    'send_file',
    'php_backdoor',
    'hash_check',
    'base64_converter',
    'address_info',
    'hex_converter',
    'page_contents',
    'password_checker',
    'fake_identity',
    'web_spider',
    'ssl_cert',
    'bash',
    'whois',
    'crypto',
    'no_endian',
    'cheat_sheet',
    'useful_links',
    'opcodes',
    'help',
    'resources',
    'modules'
]

TABCOMP = OPTIONS_SL


def completer(text, state):
    """Tab complete."""
    options = [x for x in TABCOMP if x.startswith(text)]

    try:
        return options[state]

    except IndexError:
        return None


readline.set_completer(completer)
readline.parse_and_bind("tab: complete")


def check_root():
    """Check for root privileges."""
    if not os.geteuid() == 0 and not os.getgid() == 0:
        return False


def banner():
    """Display the netpwn banner."""
    print colored(r'               __                       ', 'blue',)
    print colored(r'  ____   _____/  |_________  _  ______  ', 'blue')
    print colored(r' /    \_/ __ \   __\____ \ \/ \/ /    \ ', 'blue')
    print colored(r'|   |  \  ___/|  | |  |_> >     /   |  \ ', 'blue')
    print colored(r'|___|  /\___  >__| |   __/ \/\_/|___|  /', 'blue')
    print colored(r'     \/     \/     |__|              \/ ', 'blue')
    print ' '
    print colored(r'     | Created by 3XPL017         |', 'blue')
    print colored(r'     | twitter: @3XPL017GH057     |', 'blue')
    print colored(r'     | https://github.com/3XPL017 |', 'blue')
    print '\n' * 11


def modules():
    """Print available modules."""
    print ' '
    print colored('Modules', 'green')
    print colored('===================', 'green')
    print colored('reverse_shell', 'green')
    print colored('send_file', 'green')
    print colored('php_backdoor', 'green')
    print colored('hash_check', 'green')
    print colored('base64_converter', 'green')
    print colored('address_info', 'green')
    print colored('hex_converter', 'green')
    print colored('page_contents', 'green')
    print colored('password_checker', 'green')
    print colored('fake_identity', 'green')
    print colored('web_spider', 'green')
    print colored('ssl_cert', 'green')
    print colored('bash', 'green')
    print colored('whois', 'green')
    print colored('crypto', 'green')
    print colored('no_endian', 'green')
    print ' '


def list_resources():
    """List resource types."""
    print ''
    print colored('Resources', 'green')
    print colored('=============', 'green')
    print colored('useful_links', 'green')
    print colored('cheat_sheet', 'green')
    print colored('opcodes', 'green')
    print ''


def help_menu():
    """Print help menu."""
    print ' '
    print colored('Commands', 'green')
    print colored(
        '==================================================',
        'green')
    print colored(
        '[module name]   runs the selected module', 'green')
    print colored(
        '[resource name] lists the selected resource', 'green')
    print colored(
        'modules         lists available modules', 'green')
    print colored(
        'resources       lists types of resources to list', 'green')
    print colored(
        'banner          displays the banner', 'green')
    print colored(
        'clear           clears the screen', 'green')
    print colored(
        'exit            exits netpwn', 'green')
    print ' '


def main():
    """Handle which function to run."""
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
        'hex_converter': hex_convert.hex_converter,
        'page_contents': page.page_contents,
        'password_checker': password.password_checker,
        'fake_identity': identity.fake_identity,
        'web_spider': spider.web_spider,
        'ssl_cert': cert.ssl_cert,
        'bash': cmd.bash,
        'whois': who.whois_lookup,
        'cheat_sheet': cheat_sheet.reverse_shells,
        'crypto': crypto.crypt,
        'no_endian': no_endian.no_little,
        'useful_links': links.useful_links,
        'opcodes': opcodes.list_opcodes,
        'resources': list_resources,
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

    try:
        main()
    except KeyboardInterrupt:
        print ''
        print colored('Quitting', 'yellow')
        exit(0)
