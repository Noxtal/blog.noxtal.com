---
layout: post
title: Nmap Cheatsheet
summary: A complete cheatsheet for the Nmap pentesting tool. Nmap (standing for Network Scanner) is a free and open-source tool used to discover hosts and services running on a machine's ports or on a network.
date: 2020-07-13
author: Noxtal
categories: cheatsheets
thumbnail:  nmap
tags:
 - cheatsheet
 - nmap
 - scanning
 - network
 - networking
---

A complete cheatsheet for the Nmap pentesting tool. Nmap (standing for Network Scanner) is a free and open-source tool used to discover hosts and services running on a machine's ports or on a network.

-----

- [Cheatsheet](#cheatsheet)
  - [Basic Usage](#basic-usage)
  - [Scan Types](#scan-types)
    - [Scan IP](#scan-ip)
    - [Scan Host](#scan-host)
    - [Scan range of IPs](#scan-range-of-ips)
    - [Scan Subnet](#scan-subnet)
    - [Scan from file](#scan-from-file)
  - [Port Selection](#port-selection)
    - [Single port](#single-port)
    - [Most common ports (100)](#most-common-ports-100)
    - [Range of ports](#range-of-ports)
    - [All ports](#all-ports)
  - [Port Scan Types](#port-scan-types)
    - [TCP Connect](#tcp-connect)
    - [TCP SYN scan](#tcp-syn-scan)
    - [UDP](#udp)
  - [Service and OS detection](#service-and-os-detection)
    - [Aggressive Scan](#aggressive-scan)
    - [Version Detection](#version-detection)
  - [Scripts](#scripts)
    - [Syntax](#syntax)
    - [Most Used](#most-used)
    - [Passing a Wordlist to Bruteforce Script](#passing-a-wordlist-to-bruteforce-script)
    - [IP Address Information](#ip-address-information)
    - [Set of Scripts](#set-of-scripts)
    - [Help](#help)
  - [Output to a File](#output-to-a-file)
    - [Default](#default)
    - [XML](#xml)
    - [Grep ready](#grep-ready)
    - [All](#all)
  - [Bypass Firewall (Windows)](#bypass-firewall-windows)
  - [Verbosity](#verbosity)
    - [Verbose](#verbose)
    - [Very Verbose](#very-verbose)
  - [Personnal Favorites](#personnal-favorites)
    - [Default Scan](#default-scan)
    - [Complete Scan](#complete-scan)
    - [Vulnerability Scan](#vulnerability-scan)
    - [HTTP Scan](#http-scan)
    - [MySQL Scan](#mysql-scan)
    - [FTP Scan](#ftp-scan)
    - [SMB Scan](#smb-scan)
    - [SSH Scan](#ssh-scan)

# Cheatsheet
## Basic Usage
Syntax: `nmap [SCAN TYPE] [OPTIONS] {TARGET}`

## Scan Types
### Scan IP
```bash
nmap $IP
```
### Scan Host
```bash
nmap hostname.com
```

### Scan range of IPs
```bash
nmap IP-max
```

Ex.:
```bash
nmap 192.168.1.1-20
```

### Scan Subnet
```bash
nmap IP/NUMBITS
```

Ex.:
```bash
nmap 192.168.1.0/24
```

### Scan from file
```bash
nmap -iL list.txt
```

## Port Selection
### Single port
```bash
nmap -p 80 $IP
```

### Most common ports (100)
```bash
nmap -F $IP
```

### Range of ports
```bash
nmap -p min-max $IP
```

Ex.:
```bash
nmap -p 1-100 $IP
```

### All ports
```bash
nmap -p- $IP
```

## Port Scan Types
### TCP Connect
```bash
nmap -sT $IP
```

### TCP SYN scan
*Set by default*
```bash
nmap -sS $IP
```

### UDP
```bash
nmap -sU $IP
```

## Service and OS detection
### Aggressive Scan
```bash
nmap -A $IP
```

### Version Detection
```bash
nmap -sV $IP
```

## Scripts
Scripts helps getting more specific results.

### Syntax
```bash
nmap --script=SCRIPT $IP
```
OR
```bash
nmap --script=SCRIPT1,SCRIPT2,SCRIPT3 $IP
```

### Most Used

| Script's name/ID        | Script's Purpose                                      |
|-------------------------|-------------------------------------------------------|
| default (or -sC flag)   | Default                                               |
| vuln                    | Vulnerability Scan                                    |
| http-enum               | HTTP Enumeration                                      |
| http-grep               | HTTP Search                                           |
| smb-enum-shares         | SMB Shares Enumeration                                |
| smb-enum-users          | SMB Users Enumeration                                 |
| ftp-anon                | Detect FTP Anonymous Login                            |
| ssh-brute               | SSH Bruteforce                                        |
| ftp-brute               | FTP Bruteforce                                        |
| dns-brute               | DNS Discovery (Bruteforce)                            |
| http-wordpress-enum     | Enumerate WordPress Plugins and Themes                |
| mysql-empty-password    | Detect If Login In MySQL Without Password Is Possible |
| mysql-users             | Enumerate MySQL Users                                 |
| mysql-brute             | Bruteforce MySQL                                      |

<br/>

### Passing a Wordlist to Bruteforce Script
Ex.:
```bash
nmap --script=ssh-brute --script-args userdb=usernames.lst,passwd=passwords.lst $IP
```


### IP Address Information
```bash
nmap --script=asn-query,whois,ip-geolocation-maxmind $IP
```

### Set of Scripts
Ex.:
```bash
nmap --script=smb* $IP
```

### Help
Ex.:
```bash
nmap --script-help=vuln $IP
```

## Output to a File
### Default
```bash
nmap -oN OUTPUT_FILE $IP
```

### XML
```bash
nmap -oX OUTPUT_FILE $IP
```

### Grep ready
```bash
nmap -oG OUTPUT_FILE $IP
```

### All
```bash
nmap -oA OUTPUT_FILE $IP
```
## Bypass Firewall (Windows)
```bash
nmap -Pn $IP
```

## Verbosity
### Verbose
```bash
nmap -v $IP
```

### Very Verbose
```bash
nmap -vv $IP
```

## Personnal Favorites
### Default Scan
```bash
nmap -vv -sC -sV -oN nmap.log $IP
```

### Complete Scan
```bash
nmap -vv -A -p- -oN nmap-complete.log $IP
```

### Vulnerability Scan
```bash
nmap -vv --script vuln -oN nmap-vuln.log $IP
```

### HTTP Scan
```bash
nmap -vv --script http* -oN nmap-http.log $IP
```

### MySQL Scan
```bash
nmap -vv --script mysql* -oN nmap-mysql.log $IP
```

### FTP Scan
```bash
nmap -vv --script ftp* -oN nmap-ftp.log $IP
```

### SMB Scan
```bash
nmap -vv --script smb* -oN nmap-smb.log $IP
```

### SSH Scan
```bash
nmap -vv --script ssh* -oN nmap-ssh.log $IP
```