## Macrobean: Privilege & Safety Model

Macrobean is built with a **zero-root, zero-surprise philosophy**. All features run entirely in user-space **by default**. Root access is only requested for specific, opt-in tasks, and always with clear warnings.

---

### Default Behavior (No Root Required)

By default, Macrobean:
- Runs on **unprivileged ports (e.g., 8080)**
- Requires **no global installation**
- Serves static/dynamic content from **local ZIPs**
- Executes Lua with sandboxing enabled in `--dev` mode
- Keeps all runtime artifacts in **user-owned directories** (e.g., `/tmp/`, `$HOME/`)

✅ Safe for personal use, testing, or embedding into larger apps.

---

### 🔒 When Root Access May Be Required

| Feature                                | Requires Root? | Why it needs it                         | Safer Alternative                         |
|----------------------------------------|----------------|------------------------------------------|--------------------------------------------|
| Install to `/usr/local/bin/`          | ✅ Yes         | Write permissions to system binary path | Just run `./macrobean.com` directly        |
| TLS Certificate via Let's Encrypt     | ✅ Yes         | Certbot binds to ports 80/443 + writes to `/etc/letsencrypt` | Use your own cert with `--cert` and `--key` |
| Use of privileged ports (e.g., 80/443) | ✅ Yes         | Only root can bind to ports <1024       | Use `--port 8080` or above                 |
| System service setup (`systemd`)      | ✅ Yes         | System-wide boot jobs need root         | Use `tmux`, `screen`, or background scripts |

---

### 🔐 TLS Security Defaults

- TLS is **disabled by default**
- If enabled via `--tls`, you **must** provide:
  - A certificate (`--cert <cert.pem>`)
  - A private key (`--key <key.pem>`)
- Macrobean will never auto-fetch or trust unknown certificates silently

---

### ⚠️ Runtime Hardening

- Unsafe operations like `strcpy`, `sprintf`, etc., are replaced with bounded versions
- Dev mode (`--dev`) enables debugging, verbose logs, and Lua sandbox
- Production mode disables reloads, introspection, and avoids `fork()` unless explicitly allowed

---

### Recommendations

For maximum safety:
- Run on a non-root user
- Avoid `--fork` unless needed
- Always audit custom Lua scripts before embedding
- Use the bundled Admin UI only in `--dev` mode

---

**Transparency Matters**  
We believe in *trust through clarity*. No hidden installs, no phone-home behavior, no privileged execution unless explicitly requested.
