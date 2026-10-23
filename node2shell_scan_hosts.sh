#!/bin/sh
# node2shell_scan_hosts.sh - run node2shell_check.sh on every host in hosts.txt over SSH
# and merge the results into one CSV.
#
# Usage: ./node2shell_scan_hosts.sh "<account name>" "<account region>"
# Account name and region are required and are written on every CSV row and in the output
# folder name. When they are left out the script asks for them.
# Allowed characters: letters, digits, spaces and . _ - ( ) /  (up to 64).
# Put one host (or user@host) per line in hosts.txt next to this script.
# Needs key-based SSH. Runs the check as root, using sudo -n when the login user is not root.
# Writes node2shell_<account>_<region>_<timestamp>/merged.csv, one CSV per host in hosts/, and status.txt.

DIR=$(cd "$(dirname "$0")" && pwd)
HOSTS="$DIR/hosts.txt"
[ -f "$HOSTS" ] || { echo "Create $HOSTS with one host per line." >&2; exit 64; }

valid_label() {
  [ -n "$1" ] && [ ${#1} -le 64 ] || return 1
  case "$1" in
    *[!A-Za-z0-9\ ._/\(\)-]*) return 1 ;;
  esac
}

# require_label VALUE PROMPT: print a valid value, asking for it when running in a terminal
require_label() {
  val=$1
  while ! valid_label "$val"; do
    if [ ! -t 0 ]; then
      echo "Missing or invalid $2. Usage: $0 \"<account name>\" \"<account region>\"" >&2
      exit 64
    fi
    [ -n "$val" ] && echo "Invalid $2: use letters, digits, spaces and . _ - ( ) / (up to 64)." >&2
    printf 'Enter %s: ' "$2" >&2
    read -r val || exit 64
  done
  echo "$val"
}

ACCOUNT_NAME=$(require_label "$1" "account name") || exit 64
ACCOUNT_REGION=$(require_label "$2" "account region") || exit 64

TAG=$(printf '%s_%s' "$ACCOUNT_NAME" "$ACCOUNT_REGION" | tr -c 'A-Za-z0-9._-' '_')
OUT="$PWD/node2shell_${TAG}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT/hosts" || exit 1
CHECK="$DIR/node2shell_check.sh"
# Values are validated above and cannot contain quotes, so single-quoting is safe here.
ARGS="'$ACCOUNT_NAME' '$ACCOUNT_REGION'"
REMOTE="if [ \"\$(id -u)\" = 0 ]; then sh -s -- $ARGS; else sudo -n sh -s -- $ARGS; fi"
export CHECK OUT REMOTE ACCOUNT_NAME ACCOUNT_REGION

grep -vE '^[[:space:]]*(#|$)' "$HOSTS" | tr -d '\r' | xargs -P 20 -I{} sh -c '
  h=$1
  ssh -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$h" "$REMOTE" \
    < "$CHECK" > "$OUT/hosts/$h.csv" 2> "$OUT/hosts/$h.err"
  rc=$?
  case $rc in
    0) s=NOT_AFFECTED ;; 1) s=REVIEW ;; 2) s=AFFECTED ;; 255) s=UNREACHABLE ;; *) s="ERROR($rc)" ;;
  esac
  echo "$h,$s" >> "$OUT/status.txt"
  if [ $rc -eq 255 ] || [ ! -s "$OUT/hosts/$h.csv" ]; then
    printf "\"%s\",\"%s\",%s,,,none,\"\",,%s,,\"%s\"\n" "$ACCOUNT_NAME" "$ACCOUNT_REGION" "$h" "$s" \
      "$(tr "\n\"" "  " < "$OUT/hosts/$h.err")" > "$OUT/hosts/$h.csv"
  fi
' _ {}

{
  echo "account_name,account_region,host,os,runtime,source,path,version,status,running,note"
  cat "$OUT"/hosts/*.csv 2>/dev/null | grep -v '^account_name,account_region,'
} > "$OUT/merged.csv"

echo "Results: $OUT/merged.csv"
cut -d, -f2 "$OUT/status.txt" | sort | uniq -c
