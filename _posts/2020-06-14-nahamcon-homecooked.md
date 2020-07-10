---
layout: post
title: NahamCon - Homecooked
summary: An in-depth look at Homecooked from NahamCon. Special thanks to all the people behind NahamCon! 
date: 2020-06-14
author: Noxtal
categories: writeups
thumbnail:  nahamcon
tags:
 - nahamcon
 - crypto
 - python
 - primes
---

 An in-depth look at Homecooked from NahamCon. Special thanks to all the people behind NahamCon! 

-----

# Description
Crypto, 100 points
> I cannot get this to decrypt!
> Download the file below.

# Solution
### Disclaimer!
Before I start, I want to mention that I have read a really good writeup on this challenge by DaBaddest from the team Coding N Hacking Nation (link [here](https://ctftime.org/writeup/21463)). It features another solution to this challenge that is a lot simpler and better. The only difference with mine is that my final program finds the flag instantly whilst his/her still takes a bit of time to process. Anyway, in this writeup, I'm going to share how I solved it and how it made me create my first Python module (disponible [here](https://pypi.org/project/palindromicprimes/)).

For this challenge we are given a Python script named `decrypt.py`. 
```python
import base64
num = 0
count = 0
cipher_b64 = b"MTAwLDExMSwxMDAsOTYsMTEyLDIxLDIwOSwxNjYsMjE2LDE0MCwzMzAsMzE4LDMyMSw3MDIyMSw3MDQxNCw3MDU0NCw3MTQxNCw3MTgxMCw3MjIxMSw3MjgyNyw3MzAwMCw3MzMxOSw3MzcyMiw3NDA4OCw3NDY0Myw3NTU0MiwxMDAyOTAzLDEwMDgwOTQsMTAyMjA4OSwxMDI4MTA0LDEwMzUzMzcsMTA0MzQ0OCwxMDU1NTg3LDEwNjI1NDEsMTA2NTcxNSwxMDc0NzQ5LDEwODI4NDQsMTA4NTY5NiwxMDkyOTY2LDEwOTQwMDA="

def a(num):
    if (num > 1):
        for i in range(2,num):
            if (num % i) == 0:
                return False
                break
        return True
    else:
        return False
       
def b(num):
    my_str = str(num)
    rev_str = reversed(my_str)
    if list(my_str) == list(rev_str):
       return True
    else:
       return False


cipher = base64.b64decode(cipher_b64).decode().split(",")

while(count < len(cipher)):
    if (a(num)):
        if (b(num)):
            print(chr(int(cipher[count]) ^ num), end='', flush=True)
            count += 1
            if (count == 13):
                num = 50000
            if (count == 26):
                num = 500000
    else:
        pass
    num+=1

print()
```

At first, it seems a bit odd that we are given the program to decrypt the ciphertext, but we soon find out the twist. When we run this file, some characters pop out from the decryption, giving the start of the flag: `flag{pR1m3s_4`. Then, something weird happens: the program hangs and no more characters are output. Let's take a deeper look at the program above to see why this happens. 

The program starts by declaring a num and count variable as well as the ciphertext encoded in base64. Then, two functions returning booleans are declared. The first one, *a*, checks if the *num* parameter is a prime or not. The second one, *b*, checks if the string version of the *num* parameter is the same reversed. This is basically a check to see if the *num* parameter is palindromic.

The last part of the program is the decryption process. First, the ciphertext is decoded from base64 and put in that *cipher* variable. Then, while the *count* variable (referring to the current count of characters) is less than the cipher length, the cipher runs its main loop.

First, it checks if the *num* variable is prime. Then, it checks if it's palindromic. If both of those checks yielded true, the cipher adds the decrypted character decrypted using *num* to the result. Then, the count variable goes up by one because one character as been added to the decrypted plaintext. Finally comes the bit of code that makes the whole program slow down and hang: at the 13th character, the *num* variable is set to 50000. The same procedure applies for the 26th letter, except the *num* variable is set to 500000. As there is a lot a possible divisor to check to know if the number is prime or not and as those palindromic primes are scarce, the program needs to search for a lot of numbers, thus taking a big amount of time.

My solution to the problem was to use a big list of all palprimes (palindromic primes). I finally ended up doing a quick and dirty way to solve this problem for the sake of the CTF, but I came back to it the next day. I decided to create a Python module for finding palindromic primes really quickly using both a list and caching. The documentation can be found [here](https://github.com/Noxtal/palindromicprimes/).

```python
import base64
import palindromicprimes as palprimes
i = 0
count = 0
cipher_b64 = b"MTAwLDExMSwxMDAsOTYsMTEyLDIxLDIwOSwxNjYsMjE2LDE0MCwzMzAsMzE4LDMyMSw3MDIyMSw3MDQxNCw3MDU0NCw3MTQxNCw3MTgxMCw3MjIxMSw3MjgyNyw3MzAwMCw3MzMxOSw3MzcyMiw3NDA4OCw3NDY0Myw3NTU0MiwxMDAyOTAzLDEwMDgwOTQsMTAyMjA4OSwxMDI4MTA0LDEwMzUzMzcsMTA0MzQ0OCwxMDU1NTg3LDEwNjI1NDEsMTA2NTcxNSwxMDc0NzQ5LDEwODI4NDQsMTA4NTY5NiwxMDkyOTY2LDEwOTQwMDA="


def isprime(num):
    if (num > 1):
        for i in range(2, num):
            if (num % i) == 0:
                return False
                break
        return True
    else:
        return False


def ispalindrome(num):
    my_str = str(num)
    rev_str = reversed(my_str)
    if list(my_str) == list(rev_str):
        return True
    else:
        return False


cipher = base64.b64decode(cipher_b64).decode().split(",")

while(count < len(cipher)):
    print(chr(int(cipher[count]) ^
              palprimes.nthPalindromicPrime(i)), end='', flush=True)
    count += 1
    if (count == 13):
        i, _ = palprimes.lowestNearestPalindromicPrime(50000)
    if (count == 26):
        i, _ = palprimes.lowestNearestPalindromicPrime(500000)

    i += 1

print()
```
After including my module in the code, this is the final script I ended up sticking with. This solution is definitely not the simplest, but it has been the quickest hopefully.

That's all we got to do to solve this challenge. Obviously, I can't say it enough, special thanks to everybody behind NahamCon!

