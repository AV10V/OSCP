#!/usr/bin/env bash
# gencreds_charlie_7f3a.sh
# Build targeted username/password lists from names harvested from FTP metadata.
# Usage: ./gencreds_charlie_7f3a.sh names.txt [users.txt] [pw.txt]
# names.txt: one name per line, e.g. "Cassie Smith" or "Robert Mark" or "cassie"
set -euo pipefail

names_file="${1:-names.txt}"
out_users="${2:-users.txt}"
out_pw="${3:-pw.txt}"

if [ ! -s "$names_file" ]; then
  echo "ERROR: '$names_file' missing or empty. Put one author name per line." >&2
  exit 1
fi

tmp_users=$(mktemp)
tmp_pw=$(mktemp)
# shellcheck disable=SC2064
trap "rm -f '$tmp_users' '$tmp_pw'" EXIT

while IFS= read -r raw; do
  # trim, collapse whitespace, strip CR
  name=$(printf '%s' "$raw" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/[[:space:]][[:space:]]*/ /g')
  [ -n "$name" ] || continue

  lower=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')

  set -- $lower
  first="$1"
  shift || true
  last="${1:-}"

  # --- usernames -----------------------------------------------------------
  printf '%s\n' "$first" >> "$tmp_users"
  if [ -n "$last" ]; then
    printf '%s\n' "${first}${last}" >> "$tmp_users"
    printf '%s\n' "${first}.${last}" >> "$tmp_users"
    printf '%s\n' "${first}_${last}" >> "$tmp_users"
    printf '%s\n' "${first:0:1}${last}" >> "$tmp_users"
  fi

  # --- passwords -----------------------------------------------------------
  # every username token and every name part, in three casings, plus suffixes
  {
    printf '%s\n' "$lower"
    printf '%s\n' "$first"
    if [ -n "$last" ]; then printf '%s\n' "$last"; printf '%s\n' "${first}${last}"; fi
  } | while IFS= read -r tok; do
    tok=$(printf '%s' "$tok" | tr -d ' ')
    [ -n "$tok" ] || continue
    cap=$(printf '%s' "$tok" | sed 's/^\(.\)/\U\1/')
    up=$(printf '%s' "$tok" | tr '[:lower:]' '[:upper:]')
    for v in "$tok" "$cap" "$up"; do
      printf '%s\n' "$v" >> "$tmp_pw"
      for suf in 1 12 123 '123!' '!' 2022 2023; do
        printf '%s%s\n' "$v" "$suf" >> "$tmp_pw"
      done
      printf '!%s\n' "$v" >> "$tmp_pw"
    done
  done
done < "$names_file"

sort -u "$tmp_users" > "$out_users"
sort -u "$tmp_pw" > "$out_pw"

# usernames are also plausible passwords
{ cat "$out_users"; cat "$out_pw"; } | sort -u > "${out_pw}.tmp" && mv "${out_pw}.tmp" "$out_pw"

echo "usernames: $(wc -l < "$out_users")  -> $out_users"
echo "passwords: $(wc -l < "$out_pw")  -> $out_pw"
echo
echo "--- usernames ---"
cat "$out_users"
