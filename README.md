# netpwn
A framework made to automate tasks of pentesting.
Written in python 2.7 <br />

__Modules__ <br />
reverse_shell - Creates a reverse shell with python to connect to a specific machine of your choice. <br />
send_file - Allows you to send a file to target server. <br />
php_backdoor - Generates a simple backdoor in php upload to web server ?cmd= to execute commands. <br />
hash_check - Paste a hash to see what type of hash it is. <br />
base64_converter - Paste base64 to decode or ascii to encode it knows which you want. <br />
address_info - Gives you your ipv4, ipv6, and public Ip address based upon a interface. <br />
hex_converter - Paste some ascii to encode or hex to decode it knows which you want. <br />
page_contents - Get the raw HTML of a given web page. <br />
password_checker - Check the strength of a given password. <br />
fake_identity - Creates a fake name with SSN, address, credit card number, etc. <br />
web_spider - Crawls a given URL for links. <br />
ssl_cert - Gets the cert information of a given web site and its public key. <br />
bash - Execute bash commands without exiting out of netpwn. <br />
whois - Performs whois on a given URL. <br />
crypto - Encrypts or decrypts a file with AES. <br />
no_endian - Removes endianness  on DWORDS. <br />
rot13_converter - Encodes/decodes rot13. <br />
url_converter - Url encoded and decodes string. <br />
html_converter - Html enconded and decodes string.

__Resources__ <br />
cheat_sheet - Pentest monkey reverse shell cheat sheet <br />
opcodes - Prints out all x86 OpCodes. <br />
useful_links - Links to blogs, youtube channels, and other resources that 
    offer good information about various topics that gives you the
    opportunity to learn more about the infosec field.

__Usage__ <br />
To run a specific module just type module name. <br />
For example to run php_backdoor the command should look like this. <br />
(netpwn) > php_backdoor

__Features__ <br />
AutoComplete - Type a few letters of the command you want and hit tab to for auto completion. <br />
clear - Type this to clear the screen. <br />
banner - Type this command to display the banner. <br />
help - Type this command to display help menu. <br />
modules - Type this command to list available modules. <br />
resources - Type this command to list available resources. <br />
exit or CTRL^C - Exits netpwn

[![netpwn](https://github.com/3XPL017/netpwn/blob/master/images/netpwn.png)
[![modules](https://github.com/3XPL017/netpwn/blob/master/images/modules.png)
[![help and resources](https://github.com/3XPL017/netpwn/blob/master/images/resources.png)


### Install
#git clone https://github.com/3XPL017/netpwn.git; cd netpwn; chmod +x install; ./install

### Twitter
https://twitter.com/3XPL017GH057
