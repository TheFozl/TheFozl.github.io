---
title: formAlity
author: Fozl
event: ShutlockCTF 2025
categories: [ShutlockCTF_2025, Web]
date: 2025-07-01
tags:
  - jwt
  - auth-bypass
  - ssti
  - rce
info:
  description: Welcome to the Cannes Film Festival website. On this site you will find a film survey. You can also contact an administrator to generate a proof of attendance.
  difficulty: 2
img_path: /assets/img/Writeups/ShutlockCTF_2025/Web/formAlity/
image:
  path: /assets/img/Writeups/ShutlockCTF_2025/shutlock2025.png
---

## Challenge Description

{{ page.info.description }}

## Recon & Enumeration

We land on a site featuring a movie-themed survey.

![]({{ page.img_path }}187d5caef55c47f39af250faf124b32c.png)

After creating an account, we check the profile page and see our role is just `user`, with limited access to some pages.

![]({{ page.img_path }}7e8a2e30c74346fc8badb007e1b96cdc.png)

We poke around the survey form but find nothing exploitable at first glance. However, there is a "Justificatif" page that's inaccessible to us.

## JWT Bypass to Admin

Inspecting the session cookies, we notice the site uses a JWT. Decoding it via [token.dev](https://token.dev) reveals our role is `"user"`.

We try to escalate privileges by modifying the token:

- Change `"role": "user"` to `"role": "admin"`
- Change the algorithm from `HS256` to `none`

> Since the server does not verify the signature properly, the token is accepted with `alg: none`.

Success — we're now admin.

With admin rights, we gain access to a form to generate a proof of attendance.

![]({{ page.img_path }}ce82dd88996e4e7f8cc325c70397ddc4.png)

The form takes a first and last name and generates a PDF.

![]({{ page.img_path }}1e32840a8c1f4f4aa8b2223e6e3c1259.png)

## SSTI to RCE

Injecting some classic SSTI strings into the name fields reveals a Server-Side Template Injection vulnerability. We exploit this using a payload from [PayloadAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection):

### Payload:

{% raw %}
```javascript
{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id;ls"]}}{{a.stdio=[w,w]}}{{process.binding("spawn_sync").spawn(a).output}}
```
{% endraw %}

![]({{ page.img_path }}9ba7a33b6fea4a628a6e846920ce42a1.png)

The command runs on the server.

We don’t even need a reverse shell the flag is here, we simply trigger another payload with:

```bash
cat flag.txt
```

And we get:

```
SHLK{JwT_bYpaS5_2_RCe}
```

## TL;DR

- JWT implementation was vulnerable to `alg: none` → privilege escalation to admin
- Admin-only form renders unsanitized input in a PDF using a template engine
- SSTI leads to RCE via NodeJS payload
- We dump the flag directly with `cat`
