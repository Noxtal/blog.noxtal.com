---
layout: post
title: H@cktivityCon - Template Shack
summary: An in-depth look at Template Shack from the amazing H@cktivityCon. Thanks to every person behind this CTF, I loved playing it with my team!
date: 2020-08-02
categories: writeups
author: Noxtal
thumbnail: hacktivitycon
tags:
- hacktivitycon
- web
- jwt
- ssti
- flask
- jinja
---

 An in-depth look at Template Shack from the amazing H@cktivityCon. Thanks to every person behind this CTF, I loved playing it with [my team](https://discord.com/invite/CDACNFg)!

-----

# Description
Web, 150 points
> Check out the coolest web templates online!
> Connect here:
> http://jh2i.com:50023

# Solution
Let's start by opening the web application.

![Template Shack](https://i.imgur.com/EZZKmB7.png)

We are given a site selling website templates. As you can probably see, there is a login functionality, but no way of registering. That must be for admins only. By looking at the page's source, we can find an interesting *TODO* note.

![TODO Comment](https://i.imgur.com/nvdPUbZ.png)

That confirms that there is an admin section, let's try to access it. I first tried `/admin` which finally was the right path. The only problem is that we get a 401 unauthorized error code (which is obvious). By checking in the Developer Tools, we can find a JWT cookie named *token*. We can use [jwt.io](https://jwt.io/)'s awesome JWT debugger to get information from that token.

![JWT Debug](https://i.imgur.com/lWS5hF2.png)


## JWT - Weak Secret
If somewhat we could change the *username* value in the payload from "guest" to "admin" we should supposedly get access to the unfinished admin section. I tried some common JWT attacks until I found the working one: cracking a weak secret. By cracking the secret, we can sign any token we want. This property comes from how JWT works. If you want to learn more about it, check [jwt.io](https://jwt.io/introduction/).

Let's use JohnTheRipper to crack the secret.

```bash
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0In0.9SvIFMTsXt2gYNRF9I0ZhRhLQViY-MN7VaUutz9NA9Y" > for_john.hash
john for_john.hash -w=/usr/share/wordlists/rockyou.txt
```

In a short amount of time (a few milliseconds on my laptop), we get the secret "supersecret". We can now sign an admin token. This can be done easily using, again, [jwt.io](https://jwt.io/)'s JWT debugger.

![Signing an Admin Token](https://i.imgur.com/pptSoM9.png)

Let's now input that in the *token*'s cookie value and we get the access to the admin section. At this point, I thought this was the end, but I couldn't find the flag anywhere. After having a brief conversation with [xCthulhu](https://onoma.cf/), one of my teammates who had solved this challenge, I was told to go further, and that there was another bug to exploit.

## Server-Side Template Injection
By messing around with the admin panel, we can find that there is a custom 404 page (as seen when clicking on *Charts* or *Tables*). In Flask web applications using Jinja2's templating language, this can often lead to an SSTI, or Server-Side Template Injection. You can test for this by passing an expression between two sets of brackets (because that is how Jinja2 works). For instance, by trying to reach the page {% raw %}`{{ 2+2 }}`{% endraw %}, the 404 page should display `/admin/4` (the expression would be evaluated).

![SSTI](https://i.imgur.com/edkysSa.png)

Learn more about Flask Jinja2 SSTI [here](https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee).

After a bit of tinkering, I came up with the following payload to achieve a command injection.

```
http://jh2i.com:50023/admin/%7B%7B%20''.__class__.__mro__[1].__subclasses__()[405]('ls',%20shell=True,%20stdout=-1).communicate()%20%7D%7D
```

![SSTI to Command Injection (ls)](https://i.imgur.com/o1tZ8IA.png)

The flag can be found in `admin/flag.txt`. Use the previous payload with `cat flag.txt` instead of `ls` to read that file.

This challenge, involving 2 types of bugs I hadn't encountered in CTFs that much yet, was really fun to solve. I loved H@cktivityCon, even though I had a bit of difficulty with some of the challenges that seemed less obvious to me. Anyway, thanks a lot to everybody behind it, it was a lot of fun!