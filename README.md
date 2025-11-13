🔐 JetKVM SSL Push 🔐

[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2%20%2B-blue.svg)](./LICENSE)

A small Bash utility to automatically download TLS bundles from Certmate and push them to one or more JetKVM hosts over SSH.

**What it does:**
- **Downloads** a certificate ZIP bundle from Certmate (with retries).
- **Unpacks** and validates `fullchain.pem` and `privkey.pem`.
- **Uploads** the cert and key to each JetKVM host via SSH.
- **Restarts** the JetKVM service (via `systemctl` or a fallback `pkill`) on the remote host.

**Why use it?**
- Automates rolling out TLS updates to multiple JetKVM hosts.
- Supports dry-run mode for safe testing.

--

**Requirements**
- Bash (script is POSIX-friendly with bashisms)
- `curl`, `unzip`, `file` and `openssl` (openssl optional — used to show expiry)
- `ssh` client configured with a private key that can connect to JetKVM hosts

**Files**
- `jetkvm_ssl_push.sh` : main script
- `.jetkvm.env` : environment file

**Usage**

Make the script executable and run it:

```bash
chmod +x jetkvm_ssl_push.sh
./jetkvm_ssl_push.sh
```

Dry-run (no changes will be made):

```bash
DRY_RUN=true ./jetkvm_ssl_push.sh
# or export DRY_RUN=true
```

**SSH notes / connectivity**
- The script uses strict SSH options by default (`StrictHostKeyChecking=yes`, `BatchMode=yes`) to avoid password prompts. Pre-seed `known_hosts` if needed:

```bash
ssh-keyscan -H jetkvm1.example.com >> ~/.ssh/known_hosts
chmod 600 ~/.ssh/known_hosts
```

- Ensure your private key permissions are correct:

```bash
chmod 600 /path/to/jetkvm_rsa
```

**What the script does (high level)**
- Loads `.jetkvm.env` and validates required variables.
- For each `host|certname` entry:
  - Downloads the cert bundle from `${CERTMATE_BASE}/${certname}/tls` with retries.
  - Verifies the archive is a ZIP and contains `fullchain.pem` and `privkey.pem`.
  - Uploads `fullchain.pem` to `/userdata/jetkvm/tls/user-defined.crt` and `privkey.pem` to `/userdata/jetkvm/tls/user-defined.key` on the remote host.
  - Restarts `jetkvm` (or `kvm`) service via `systemctl`, or falls back to `pkill -f jetkvm_app`.

**Troubleshooting**
- Can't SSH/connect: verify `SSH_KEY`, `JETKVM_USER`, and that host is reachable. Try `ssh -i /path/to/key user@host` locally.
- Host key verification failures: use `ssh-keyscan` as shown above.
- Download failures: the script writes partial/error files to a temporary workdir. If a download repeatedly fails, inspect the saved files and the `CERTMATE_TOKEN` and `CERTMATE_BASE` values.
- Missing files in ZIP: ensure your Certmate `/tls` endpoint returns a ZIP containing `fullchain.pem` and `privkey.pem`.

**Error preservation**
If an error occurs the script sets `KEEP_ERRORS=true` and preserves the temp workdir so you can inspect the saved artifacts and SSH logs. The path will be printed in the logs.

**Security / Safety**
- The script intentionally uses strict SSH and non-interactive modes to avoid accidental prompts.
- Keep your private keys secure and limit access to the `.jetkvm.env` file.

**Contributing**
Feel free to open issues or PRs with improvements.

📄 License
___
This project is licensed under the GNU General Public License v2 (or later) - see the `LICENSE` file for details.

---

<p align="center">
Made with ❤️ by Kyle Britton
<br>
⭐ <a href="https://github.com/wonkygecko/JetKVM-SSL-Push">Star us on GitHub</a> • 🐛 <a href="https://github.com/wonkygecko/JetKVM-SSL-Push/issues">Report Bug</a>
</p>
