# node2shell-detect

Find systems affected by **Node2Shell** (CVE-2026-111497), a remote code execution flaw in the Brotli decoder bundled with Node.js, on Unix and Windows. Bun bundles the same decoder and is checked too. Every run must be labelled with an account name and region, which are written on every CSV row.

| Script | Platform | Run |
|---|---|---|
| `node2shell_check.sh` | Linux, macOS, *BSD, AIX, Solaris | `sudo ./node2shell_check.sh "<account>" "<region>"` |
| `node2shell_scan_hosts.sh` | Unix control node | `./node2shell_scan_hosts.sh "<account>" "<region>"` (reads `hosts.txt`) |
| `Find-Node2Shell.ps1` | Windows | `.\Find-Node2Shell.ps1 -AccountName "<account>" -AccountRegion "<region>"` (elevated) |
| `Invoke-Node2ShellScan.ps1` | Windows control node | `.\Invoke-Node2ShellScan.ps1 -AccountName "<account>" -AccountRegion "<region>"` (reads `windows_hosts.txt`) |

## Account name and region

Both are required, so every CSV shows which account and region it came from.

- Leave them out when running in a terminal and the script asks for them.
- Leave them out in a non-interactive run (SSH, Ansible, scheduled task) and the script stops with exit code `64` instead of writing an unlabelled report.
- Allowed characters: letters, digits, spaces and `. _ - ( ) /`, up to 64. Example: `"Acme Payments (Prod)" "eu-west-1"`.
- The multi-host scanners also put them in the output name.

## Fixed versions built in

| Line | First fixed release |
|---|---|
| Node.js 26 | 26.12.1 |
| Node.js 24 | 24.22.1 |
| Node.js 22 | 22.23.4 |
| Node.js 25, 23, 20 and older | No fix: `AFFECTED_EOL` |
| Bun | 1.4.4 |

Released 21 Oct 2026. Confirm against the [Node.js security blog](https://nodejs.org/en/blog/vulnerability). If they change, edit the `FIXED` and `BUN_FIXED` lines at the top of `node2shell_check.sh` and the `$FixedMap` and `$BunFixed` lines at the top of `Find-Node2Shell.ps1`.

## Scanning many hosts

- **Unix:** put one host (or `user@host`) per line in `hosts.txt` next to the scripts, then run `./node2shell_scan_hosts.sh "<account>" "<region>"`. Needs key-based SSH; the check runs as root, using `sudo -n` when the login user is not root. Results go to `node2shell_<account>_<region>_<timestamp>/merged.csv`.
- **Windows:** put one host per line in `windows_hosts.txt` next to the scripts, then run `.\Invoke-Node2ShellScan.ps1 -AccountName "<account>" -AccountRegion "<region>"`. Uses WinRM and your current credentials. Results go to `node2shell_windows_<account>_<region>_<timestamp>.csv`.
- **Ansible:** `ansible all -b -m script -a 'node2shell_check.sh "<account>" "<region>"'`

Host lists and results are excluded from git by `.gitignore`.

## What is checked

- **Unix:** PATH, package and vendor layouts (`/usr/local`, `/opt`, Red Hat SCL, Bitnami, Homebrew, `n`), version managers in every user's home (nvm, fnm, Volta, asdf, Bun), running `node`/`bun` processes, OS packages (rpm, dpkg, apk, FreeBSD pkg) and running Docker/Podman containers.
- **Windows:** PATH, running processes, IIS iisnode (`applicationHost.config`) and common install folders (Program Files, nvm-windows, fnm, Volta, Scoop, Chocolatey, user `.bun` folders).
- **Linux only:** a process still running a Node.js binary that an upgrade has since replaced is reported as a `process` row, with the old version read from the running process. Restart it.

Versions are read from the release URL compiled into official Node.js builds, so Node.js is not run; other builds and Bun fall back to `--version`. On Windows the version comes from the file properties.

Not covered: Node.js embedded inside other applications (Electron apps, vendor products that ship their own runtime) and other software that bundles its own copy of Brotli. Check those with the vendor.

## Output

CSV columns: `account_name, account_region, host, os, runtime, source, path, version, status, running, note`

| Status | Meaning |
|---|---|
| `AFFECTED_EOL` | End-of-life Node.js line with no fix: upgrade |
| `AFFECTED` | Below the fixed release for its line |
| `NOT_AFFECTED` | At or above the fixed release |
| `REVIEW_NO_FIX_DATA` | Line with no known fix (for example a newer release line) |
| `UNKNOWN_VERSION` | Version could not be read |
| `NO_NODE_FOUND` | Nothing found in common locations |
| `UNREACHABLE` | Host could not be reached by SSH or WinRM |

Exit codes for a single-host check: `0` nothing affected, `1` needs review, `2` affected.

### Triage order

1. `AFFECTED*` with running `yes`, and every `process` row: these are services running now.
2. `container` rows: rebuild the image on a fixed base image and redeploy.
3. Other `AFFECTED*` rows (installed, not running).
4. `package` rows: some distros apply fixes without changing the version number, so check the vendor advisory.
5. `REVIEW_NO_FIX_DATA`, `UNKNOWN_VERSION`, `UNREACHABLE`, and `NO_NODE_FOUND` on hosts known to run Node.js.

### Terms used in the report

| Term | Meaning |
|---|---|
| CVE | Common Vulnerabilities and Exposures: the public ID given to a security flaw |
| Node.js | JavaScript runtime used to run web applications and APIs on servers |
| Bun | Alternative JavaScript runtime that bundles the same Brotli decoder |
| Brotli | Compression format used on the web; Node2Shell is a flaw in its decoder |
| OS | Operating system, with its kernel or build version |
| runtime | `node` or `bun` |
| binary | A Node.js or Bun program file found on disk |
| process | A running process whose program file has been replaced on disk (Linux) |
| package | Node.js installed through the operating system's package manager |
| container | Node.js or Bun found inside a running Docker or Podman container |
| IIS / iisnode | Internet Information Services, the Windows web server, and its module for hosting Node.js |
| EOL | End of life: a release line that no longer gets security fixes |
| SSH | Secure Shell: how the Unix scanner connects to each host |
| WinRM | Windows Remote Management: how the Windows scanner connects to each host |
| running `yes` / `no` / `-` | `yes`: in use now; `no`: installed but not in use; `-`: not checked (package rows) |
