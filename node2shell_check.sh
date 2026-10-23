#!/bin/sh
# node2shell_check.sh - find Node.js (and Bun) installs affected by Node2Shell
# (CVE-2026-111497) on Linux, macOS, *BSD, AIX and Solaris.
#
# Usage: sudo ./node2shell_check.sh "<account name>" "<account region>"
# Account name and region are required and are written on every CSV row. When they are left out
# the script asks for them, or stops if it is not running in a terminal.
# Allowed characters: letters, digits, spaces and . _ - ( ) /  (up to 64).
# Prints a CSV report. Exit code: 0 nothing affected, 1 needs review, 2 affected, 64 missing account details.

# First fixed release per Node.js major line (security releases of 21 Oct 2026).
# Other lines below the newest fixed one (25, 23, 20 and older) are end-of-life with no fix.
# Bun bundles the same Brotli decoder and is fixed in BUN_FIXED.
# Confirm against https://nodejs.org/en/blog/vulnerability before relying on the results.
FIXED="22=22.23.4,24=24.22.1,26=26.12.1"
BUN_FIXED="1.4.4"

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
LC_ALL=C
export PATH LC_ALL

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

HOST=$(hostname 2>/dev/null || uname -n)
OS="$(uname -s) $(uname -r)"
TMP="${TMPDIR:-/tmp}/node2shell.$$"
trap 'rm -f "$TMP".*' EXIT
trap 'exit 130' INT TERM
: > "$TMP.seen"
: > "$TMP.run"
WORST=0
FOUND=0
PS_OUT=$(ps -ef 2>/dev/null || ps aux 2>/dev/null)

# ---------- helpers ----------

norm_ver() {
  echo "$1" | sed -n 's/^[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p'
}

# succeeds when $1 < $2 (major.minor.patch)
ver_lt() {
  awk -v a="$1" -v b="$2" 'BEGIN { split(a, x, "."); split(b, y, ".")
    for (i = 1; i <= 3; i++) { if (x[i] + 0 < y[i] + 0) exit 0; if (x[i] + 0 > y[i] + 0) exit 1 }
    exit 1 }'
}

fixed_for() {
  echo "$FIXED" | tr ',' '\n' | sed -n "s/^ *$1 *= *\([0-9][0-9.]*\) *\$/\1/p" | head -1
}

newest_fixed_major() {
  echo "$FIXED" | tr ',' '\n' | sed 's/=.*//; s/ //g' | sort -n | tail -1
}

runtime_of() {
  case "${1##*/}" in
    bun*) echo bun ;;
    *) echo node ;;
  esac
}

# Release builds of Node.js carry their download URL, so the version can be read
# from the binary without running it. Other builds fall back to --version.
bin_version() {
  if [ "$(runtime_of "$1")" = node ]; then
    v=$(grep -aoE 'node-v[0-9]+\.[0-9]+\.[0-9]+-headers' "$1" 2>/dev/null | head -1)
  else
    v=
  fi
  [ -z "$v" ] && v=$("$1" --version 2>/dev/null </dev/null | head -1)
  norm_ver "$v"
}

realp() {
  readlink -f "$1" 2>/dev/null || echo "$1"
}

bin_running() {
  if grep -qxF "$1" "$TMP.run"; then echo yes; else echo no; fi
}

classify() {
  rt=$1; v=$2
  if [ -z "$v" ]; then STATUS=UNKNOWN_VERSION; NOTE="could not read version"; return; fi
  if [ "$rt" = bun ]; then
    if ver_lt "$v" "$BUN_FIXED"; then STATUS=AFFECTED; NOTE="below fixed Bun $BUN_FIXED"
    else STATUS=NOT_AFFECTED; NOTE="at or above fixed Bun $BUN_FIXED"; fi
    return
  fi
  maj=${v%%.*}
  fx=$(fixed_for "$maj")
  if [ -n "$fx" ]; then
    if ver_lt "$v" "$fx"; then STATUS=AFFECTED; NOTE="below fixed $fx"; else STATUS=NOT_AFFECTED; NOTE="at or above fixed $fx"; fi
    return
  fi
  if [ "$maj" -lt "$(newest_fixed_major)" ]; then
    STATUS=AFFECTED_EOL; NOTE="Node.js $maj is end-of-life with no fix: upgrade to a fixed line"; return
  fi
  STATUS=REVIEW_NO_FIX_DATA; NOTE="no fixed version known for Node.js $maj"
}

# emit RUNTIME SOURCE PATH VERSION RUNNING [EXTRA_NOTE]
emit() {
  classify "$1" "$4"
  [ -n "$6" ] && NOTE="$NOTE; $6"
  case $STATUS in
    AFFECTED*) r=2 ;;
    REVIEW*|UNKNOWN*) r=1 ;;
    *) r=0 ;;
  esac
  [ $r -gt $WORST ] && WORST=$r
  FOUND=1
  printf '"%s","%s",%s,%s,%s,%s,"%s",%s,%s,%s,"%s"\n' "$ACCOUNT_NAME" "$ACCOUNT_REGION" \
    "$HOST" "$OS" "$1" "$2" "$3" "${4:-?}" "$STATUS" "$5" "$NOTE"
}

# ---------- discovery ----------

echo "account_name,account_region,host,os,runtime,source,path,version,status,running,note"

# Running node / bun processes. On Linux /proc gives the real binary, including
# binaries replaced on disk by an upgrade whose process was never restarted.
if [ -d /proc/1 ]; then
  for d in /proc/[0-9]*; do
    exe=$(readlink "$d/exe" 2>/dev/null) || continue
    case "${exe% (deleted)}" in
      */node|*/nodejs|*/node[0-9]*|*/bun) ;;
      *) continue ;;
    esac
    case "$exe" in
      *" (deleted)")
        orig=${exe% (deleted)}
        grep -qxF "deleted:$orig" "$TMP.seen" && continue
        echo "deleted:$orig" >> "$TMP.seen"
        rt=$(runtime_of "$orig")
        if [ "$rt" = node ]; then
          v=$(norm_ver "$(grep -aoE 'node-v[0-9]+\.[0-9]+\.[0-9]+-headers' "$d/exe" 2>/dev/null | head -1)")
        else
          v=
        fi
        emit "$rt" process "$orig (replaced on disk, pid ${d#/proc/})" "$v" yes \
          "process still runs the old binary: restart it to pick up the update"
        ;;
      *) echo "$exe" >> "$TMP.run" ;;
    esac
  done
fi
echo "$PS_OUT" | grep -oE '/[^ ]*/(node|nodejs|bun)( |$)' | sed 's/ $//' > "$TMP.psp"
while IFS= read -r p; do
  realp "$p" >> "$TMP.run"
done < "$TMP.psp"

# Binaries: PATH, package and vendor layouts, version managers, running processes
{
  for n in node nodejs bun; do command -v "$n" 2>/dev/null; done
  ls -1d /usr/bin/node /usr/bin/nodejs /usr/bin/node[0-9]* /usr/local/bin/node /usr/local/bin/bun \
    /usr/local/lib/nodejs/*/bin/node /usr/local/node*/bin/node /opt/node*/bin/node /opt/*/node*/bin/node \
    /opt/rh/*nodejs*/root/usr/bin/node /opt/bitnami/node/bin/node /usr/local/n/versions/node/*/bin/node \
    /opt/homebrew/opt/node*/bin/node /usr/local/opt/node*/bin/node /opt/freeware/bin/node \
    /root/.nvm/versions/node/*/bin/node /home/*/.nvm/versions/node/*/bin/node /Users/*/.nvm/versions/node/*/bin/node \
    /root/.volta/tools/image/node/*/bin/node /home/*/.volta/tools/image/node/*/bin/node \
    /root/.local/share/fnm/node-versions/*/installation/bin/node /home/*/.local/share/fnm/node-versions/*/installation/bin/node \
    /root/.asdf/installs/nodejs/*/bin/node /home/*/.asdf/installs/nodejs/*/bin/node \
    /root/.bun/bin/bun /home/*/.bun/bin/bun /Users/*/.bun/bin/bun 2>/dev/null
  cat "$TMP.run"
} | grep -E '/(node|nodejs|node[0-9]+|bun)$' > "$TMP.cand"

while IFS= read -r p; do
  [ -f "$p" ] && [ -x "$p" ] || continue
  rp=$(realp "$p")
  grep -qxF "$rp" "$TMP.seen" && continue
  echo "$rp" >> "$TMP.seen"
  emit "$(runtime_of "$rp")" binary "$rp" "$(bin_version "$rp")" "$(bin_running "$rp")"
done < "$TMP.cand"

# OS packages. Distros may backport fixes without changing the upstream version,
# so a package row marked AFFECTED must be checked against the vendor advisory.
PKG_NOTE="distro package: vendor may have backported the fix, check vendor advisory for this release"
{
  if command -v rpm >/dev/null 2>&1; then
    rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -E '^nodejs[0-9]*\|'
  fi
  if command -v dpkg-query >/dev/null 2>&1; then
    dpkg-query -W -f='${Package}|${Version}|${Status}\n' 'nodejs*' 2>/dev/null \
      | grep 'install ok installed' | grep -E '^nodejs[0-9]*\|' | cut -d'|' -f1,2
  fi
  if command -v apk >/dev/null 2>&1; then
    apk info -v 2>/dev/null | grep -E '^nodejs(-current)?-[0-9]' \
      | sed 's/^\(nodejs\(-current\)\{0,1\}\)-\([0-9].*\)$/\1|\3/'
  fi
  if command -v pkg >/dev/null 2>&1 && [ "$(uname -s)" = FreeBSD ]; then
    pkg query '%n|%v' 2>/dev/null | grep -E '^node[0-9]*\|'
  fi
} > "$TMP.pkgs"

while IFS='|' read -r name ver; do
  [ -n "$name" ] || continue
  emit node package "$name" "$(norm_ver "${ver#*:}")" - "$PKG_NOTE (pkg $ver)"
done < "$TMP.pkgs"

# Running containers (docker / podman, when installed)
for rt in docker podman; do
  command -v "$rt" >/dev/null 2>&1 || continue
  "$rt" ps --format '{{.ID}}|{{.Image}}' 2>/dev/null > "$TMP.ctr"
  while IFS='|' read -r cid img; do
    [ -n "$cid" ] || continue
    for r in node bun; do
      v=$("$rt" exec "$cid" "$r" --version </dev/null 2>/dev/null | head -1)
      [ -n "$v" ] && emit "$r" container "$rt:$cid:$img" "$(norm_ver "$v")" yes "fix by rebuilding the image"
    done
  done < "$TMP.ctr"
done

if [ $FOUND -eq 0 ]; then
  printf '"%s","%s",%s,%s,,none,"",,NO_NODE_FOUND,,"no Node.js or Bun found in common locations"\n' \
    "$ACCOUNT_NAME" "$ACCOUNT_REGION" "$HOST" "$OS"
fi

exit $WORST
