---
layout: post
title: TryHackMe King of the Hill - Spacejam
summary:  A detailled look at the Spacejam box from TryHackMe's King of the Hill mode. Includes attack, flag locations, king tricks and patching.
date: 2020-06-16
author: Noxtal
categories: writeups
thumbnail:  tryhackme
tags:
 - tryhackme
 - koth
 - injection
---

 A detailled look at the Spacejam box from TryHackMe's King of the Hill mode. Includes attack, flag locations, king tricks and patching.

-----

### Disclaimer!
This writeup is not made for complete beginners: I will assume you know about the basics of both Linux and pen-testing. However, if you have got some questions, I would be glad to help you out. Contact me on [Twitter](https://twitter.com/noxtal_).

The names and concept of the next steps are strongly inspired by those resources:
- https://www.redlegg.com/blog/pen-test-steps.
- https://koth.cs.umd.edu/

# Attacking
## Reconnaissance
Let's do a typical reconnaissance at the surface of the box: port scanning and directory busting. 

Here are the principal scans I always run on the machine.
1. `nmap -vv -sC -sV -oN nmap.log <MACHINE_IP>`. This scan uses the default NSE scripts, making it safe and useful for discovery. It also attemps to get the version on the port of 
2. `nmap -vv --script vuln -oN nmap-vuln.log <MACHINE_IP>` which detects potential vulnerabilities on every port of the machine.
3. `gobuster dir -w /usr/share/wordlists/dirb/common.txt -o gobuster.log -u <MACHINE_IP>`. I use *gobuster* for directory busting with the dirb's common directory dictionary.

I prefer to run the vulnerability scan in parallel with another simple scan because it can take a while to run. Also, I use its result only as a backup solution if I can find anything useful in it.

Finally, notice that I log every scan results, so I can read them later and clear those terminals without a problem.

Done with my personal method, let's now analyze what we have got.

There is nothing really interesting on the *gobuster* scan, consisting mostly of rabbit holes. The *nmap* vulnerability scan has not returned anything good for the exploitation. We will then use the simple *nmap* scan as a guide.

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 1d:f0:d5:f2:67:1e:55:99:de:c6:26:85:b3:86:ea:81 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3bZ4ImRR00WoZVof42Lm+fDsOCS4QRa+Nm67gzMEXHsUrFLXZCMfFv9N7X3S1nmVxy2W7Xw1UzhDXEx+few0UItsLMqORBQt19sXrLNGfbjGHlm5BRF8/MVqU16o13dO0qZd42Ca16ZdipgaiG40h9MOkAAj/932QZs57Y6NWq0/FSbTNKGO/HJpfzWfv9RF33JPNqiGcMSuAXaUttFqPb9qcx0GtrBIgJ8Dlz/eH4mCVK/7sYT+NHlaEIjdSDwAEZKdmFVsp3frSZFIKez1Iw/UgzzgrPSxIiAxBheHUpLgZWbgXLhHogHTZNqDW8CY6s65LQML1+wzEljVUORtf
|   256 4f:5f:62:98:aa:b1:dd:a2:81:61:16:9b:a5:29:cd:bd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIqQCmLL3/kioGb5KVnJyue60AW1vy3+/b+6gpnVpQ+UDINt6oyLefIRPxi5bIGror3uo/dqSsWDi/wU1zfo+7A=
|   256 9b:12:b0:f3:1f:fb:b7:d8:a8:9c:6b:e6:bd:f4:40:55 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMcjqhfwtK4R8OiqGI2BZZTDkQF6M/ycOM6t8s37hGP0
23/tcp   open  telnet  syn-ack ttl 61 Linux telnetd
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Michael Jordan
3000/tcp open  http    syn-ack ttl 61 Node.js (Express middleware)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
```
(I have cut the part of the 9999 port because it is TryHackMe's port)

There is a classical SSH open port along with Telnet, but the most interesting ports are the two last. As you can see, they are running an HTTP server. The first one listed, port 80, runs Apache whereas the second one, port 3000, runs Node.js.

Port 80 is really just a simple blog. Using the directory found in the *gobuster* scan, we can seek the entire website. By taking an overall look at it, I have found no potential vulnerabilities there.

![Website](https://i.imgur.com/RP3ZfXk.png)

Let's instead head up to port 3000. As soon as we arrive, we can find a very interesting message telling us the *cmd* argument is missing... Are we facing a command injection? Let's take a closer look at this.

![Port 3000](https://i.imgur.com/ZYsKlK9.png)

## Vulnerability Assessment
Let's try to run a typical UNIX command, for instance, `ls`, as the *cmd* argument to see if we get the result expected.
![Successful ls](https://i.imgur.com/gPYrrBb.png)

As you can see, the command output has been output on the screen. Hence, we have now a command injection we can use to spawn a reverse shell, for example. Even better: by typing the command `whoami, we can find that this command injection will give us root access, which means no privelege escalation will be needed.

## Penetration Testing
We now need to spawn a shell inside. 

First, let's setup a listener on port 4444 using netcat: `nc -lvnp 4444`.

Second, let's use the well-known Reverse Shell Cheatsheet by pentestmonkey as our reverse shell client. I used the Python oneliner but some others may work too. Pass it into the *cmd* argument and there you go!
`http://<IP>/?cmd=<REVERSE_SHELL>`

## Lateral Movement (Pivoting)
We are in, so we now need to pivot and both find all the flags and become king to get as many points as possible.

### Become King
Here is a classical method to become king.
1. Make sure you have the root permissions (use the `whoami` command if you are not sure, but using the vulnerability exploited before you should be).
2. Replace the content of the king.txt file (*/root/king.txt*) with your username. This can be done easily using a simple echo command: `echo "USERNAME" > /root/king.txt`.
    * If you can't access the king file (*permission denied*), another player has doubtlessly used the *chattr* command to make the file immutable (explained in the next point). To remove that immutability flag, run the following command: `chattr -i /root/king.txt`.
3. Use the *chattr* to set an immutability flag on the king.txt file. This will disable every user (even root) to edit the file unless they run the last-mentioned command. The *chattr* command we need to use for that is the following: `chattr +i /root/king.txt`. Here the `+` means "add the attribute to the file" whilst the `-` in the command before meant the opposite. Right next to this sign, we specify the attribute. In our case, we use "i" for "immutable". Finally, we specify the file we want to affect (the king.txt file in this case). The file should now have another layer of protection to your advantage.

### Flags
There are two flags in this box. The first one is a user flag, located in both */home/bunny/user.txt* and in */home/jordan/user.txt* (the flag is the same). The second one is the root flag and is located, as usual on THM boxes, in */root/root.txt*.

# Defending 
## Patching
To be sure no one comes in by the way we took, we need to patch the command injection, strongly limiting the count of possible vulnerabilities. 

Before doing that, be sure you have installed a backdoor so you won't be locked out if you lost your reverse shell. This can be done by multiple manners, but the easiest (but surely not the best) way is to add yourself a user in the machine so you can ssh to it without a problem.

To patch the vulnerability, let's first find where is the server. 

First, let's find which process is running on port 3000 using netstat.
`netstat -nlp | grep 3000`

Running this command should give you an output looking like that.

![Netstat](https://i.imgur.com/lzMVAoO.png)

Where *\<PROCESS ID\>* is the PID we are looking for. Now, we need to find what is running on this PID. Let's use the *ps* command which stands for *Process Status*. To search for a PID we need to specify the *-p* flag followed by the PID (`ps -p <PROCESS ID>`). You should get an output looking like that:

![Process](https://i.imgur.com/xCK81TJ.png)

We have now located the server. Let's take a look at it:
```javascript
const express = require('express')
const app = express()
const { exec } = require('child_process');

app.get('/', (req, res) => {
    var param = req.query.cmd
    if(!param){
        res.send("the cmd parameter is undefined")
    }
    exec(param, (err, stdout, stderr) => {
        if(err){
            console.log("there was an error running your command")
            console.log(err)
            res.send("there was an error running your command" + err)
        }
        else{
            res.send(stdout + '\n' + stderr)
        }
    })
})

app.listen(3000, () => console.log('App listening on port 3000!'));
```

This program is a Node.js Express server. If you are not familiar with Javascript and Node.js you might need to check it out.

Now let's patch. We need to remove everything related to the command injection. It is important to let the server run correctly as, for the game to stay fair and fun, we need to use as few superman defences as possible (we should use them only if there is not any other solution possible). This is mentioned in TryHackMe KOTH rules.

You can add barely any feature to server.js as you want as long as you don't use it to attack other players, which is strictly illegal, and unfair. Use that server to troll and tease other players if you want, or even to do a shoutout to yourself, as I did. Those are all legal things to do which makes the game a lot more fun.

My version:
```javascript
const express = require('express')
const app = express()
const { exec } = require('child_process')
app.get('/', (req, res) => {
    res.send("Patched by Noxtal! @noxtal_ on Twitter, I would be glad to talk. :) Website: noxtal.com.")
})
app.listen(3000, () => console.log('App listening on port 3000'))
```

Once you are done we need to update the server with the current version of the server. In order to do that, kill the previously found process id (using, for instance `kill -9 <PROCESS ID>`). Then, as soon as possible, put the server back up using the node command: `node server.js`. Your patching job is now done! 

That's what I achieved to find on that box. If you have any questions, feedback or other information I have not listed, feel free to contact me via [Twitter](https://twitter.com/noxtal_) or using any of the methods listed [here](https://writeups.noxtal.com/#/pages/about).