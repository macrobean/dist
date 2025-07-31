> [!WARNING]
> macrobean have not received external security review and may contain vulnerabilities. Do not store sensitive data on it, and do not rely on its security until it has been reviewed.

# Macrobean
> A local, portable, single-file web server with Lua scripting, SQLite support, and TLS encryption. Zero dependencies, zero installation.

Macrobean is a self-contained, single-binary web server designed for simplicity, security, and portability. It can serve static files, execute dynamic Lua scripts, query SQLite databases, and handle TLS (HTTPS) traffic without requiring any external runtimes, libraries, or configuration files.

It's built for developers who need to deploy simple web applications quickly, hobbyists hosting a personal site, or anyone who values a minimal, dependency-free toolchain.

## Core Features
- **Static File Serving:** Serves HTML, CSS, JS, images, fonts, and more.
- **Dynamic Scripting:** Executes `.lua` files to generate dynamic content.
- **Database Support:** Integrated SQLite3 engine, accessible from Lua.
- **Embedded Content:** All site files are bundled inside the executable for true portability.
- **TLS/HTTPS:** First-class TLS support using mbedTLS.
- **Zero Dependencies:** Runs on macOS/Linux system without installation.
- **Secure by Default:** Optional (recommended) sandboxing and process-forking for enhanced security.

---

## Getting Started

### 1. Download
Download the `macrobean.com` binary. It's already bundled in this distribution, ready to run.

### 2. Prepare Your Website
Macrobean serves files from a ZIP archive. By default, it looks for an archive embedded within its own executable, but you can point it to an external `site.zip` for development.

**Key Requirement: The ZIP archive must be uncompressed.**
Macrobean reads files directly from the archive's memory map and does not support on-the-fly decompression. This is a deliberate design choice to keep the server's footprint minimal.

Create your `site.zip` using the `-0` (store-only) flag:
```bash
# Assume your website files are in a 'site/' directory
zip -r -0 ../site.zip site/
```

Your `site/` directory should contain your website files, for example:
```
site/
├── index.html         # Main entry point
├── style.css
├── init.lua           # Optional: for dynamic routing
├── query.lua          # Optional: a Lua script
└── data.db            # Optional: your SQLite database
```

### 3. Run the Server
Execute the binary from your terminal. For development, it's best to use the `--dev`, `--lua`, and `--db` flags, pointing to your external ZIP file.

```bash
# Make the binary executable
chmod +x macrobean.com

# Run in developer mode with an external ZIP
./macrobean.com --zip site.zip --dev --lua --db
```
You should see output like this:
```
Running Macrobean Server
Loaded external ZIP: site.zip (5120 bytes)
successfully fetched 15 files from embedded archive
server running on http://localhost:8080
available files:
  - site/index.html
  - site/style.css
  - site/init.lua
...
press ctrl+c to stop
```
Now, open **http://localhost:8080** in your browser.

### 4. macOS Gatekeeper Workaround
On macOS, the first time you run a downloaded binary, Gatekeeper may block it.
> "macrobean.com is damaged and can’t be opened. You should move it to the Trash."

This is expected security behavior. To fix it, remove the quarantine attribute:
```bash
xattr -d com.apple.quarantine macrobean.com
```
You should now be able to run the binary without warnings.

---

## Command-Line Flags
Macrobean is configured entirely through command-line flags.

| Flag | Description | Default |
| --- | --- | --- |
| `--help`, `-h` | Show the help message and exit. | |
| `--port <n>` | Set the TCP port to listen on. | `8080` |
| `--dev` | **(Recommended for development)** Enables detailed logging, error tracebacks, and the admin panel. | Disabled |
| `--watch` | **(Dev only)** Enables hot-reload. Automatically reloads the external `site.zip` and `data.db` when they change. Implies `--dev`. | Disabled |
| `--zip <file>` | Use an external, uncompressed `site.zip` file instead of the one embedded in the binary. Essential for development. | Embedded ZIP |
| `--lua` | Enable the Lua scripting engine. Allows execution of `.lua` files and `init.lua` routing. | Disabled |
| `--db` | Enable the SQLite3 engine, making `db.query()` and `db.exec()` available in Lua. | Disabled |
| `--fork` | Handle each incoming request in a separate `fork()`-ed process. Provides OS-level isolation between requests. | Disabled |
| `--sandbox` | Enable a strict Lua sandbox. Restricts `os`, `io`, `package` libraries and sets an execution timeout to prevent runaway scripts. | Disabled |
| `--tls` | Enable HTTPS. Requires `--cert` and `--key`. | Disabled |
| `--cert <file>` | Path to your TLS certificate file in PEM format. | |
| `--key <file>` | Path to your TLS private key file in PEM format. | |

---

## Developer Guide

### Developer Mode (`--dev`)
The `--dev` flag is your most important tool during development. It enables:
- **Verbose Logging:** See exactly how a request is being processed.
- **Detailed Errors:** 404 pages will list available files, and Lua errors will show a full stack trace.
- **Admin Panel:** Access a simple admin UI at `http://localhost:8080/admin.html`.
- **HTTP Fallback:** If `--tls` is enabled but certs are missing, the server will fall back to HTTP with a warning instead of exiting.

### Hot-Reload (`--watch`)
When used with an external `--zip`, the `--watch` flag monitors `site.zip` for changes and automatically reloads it. This allows you to edit your site, re-run the `zip -0` command, and see the changes instantly without restarting the server.

### The Admin Panel (`admin.html`)
When in `--dev` mode, navigating to `/admin.html` provides a simple interface to inspect the server's state, including a list of all files found in the loaded ZIP archive.

---

## Dynamic Content with Lua

When `--lua` is enabled, Macrobean can execute Lua scripts.

### Handling Requests
Any request for a `.lua` file will execute that file. A global `request` table is available with the following structure:
```lua
-- Example structure of the global 'request' table
request = {
  path = "/hello/world?name=developer",
  method = "GET",
  query = {
    name = "developer"
  },
  headers = {
    Host = "localhost:8080",
    ["User-Agent"] = "curl/7.79.1"
  },
  body = "Optional request body for POST/PUT"
}
```
Your script should return a single string, which will be sent as the response with a `200 OK` status.

### Dynamic Routing (`init.lua`)
If a file named `site/init.lua` exists in your ZIP, it will be executed once on startup. This file is the ideal place to define dynamic routes that map URL patterns to functions.

**Example `site/init.lua`:**
```lua
-- This global table stores your routes.
-- The key is the path, the value is the handler function.
routes = {}

routes["/"] = function()
  return "<h1>Home Page</h1>"
end

routes["/hello"] = function()
  -- You can access the request object here
  local name = request.query.name or "World"
  return "Hello, " .. name
end

-- A simple before hook for auth
routes.before = function()
  if request.query.secret ~= "opensesame" then
    -- Returning a string from 'before' blocks the request
    return "403 Forbidden: Invalid secret"
  end
end
```

### Using the SQLite Database (`--db`)
If `--db` is enabled, a global `db` table is available in Lua. It exposes two functions that operate on a database file located at `site/data.db` within your ZIP archive.

1.  `db.query(db_path, sql_query)`: Executes a `SELECT` query and returns an array of tables (rows).
2.  `db.exec(db_path, sql_query)`: Executes a `CREATE`, `INSERT`, `UPDATE`, or `DELETE` statement and returns `true` on success.

**Example `site/query.lua`:**
```lua
-- Fetch all users from the database
local rows = db.query("site/data.db", "SELECT id, name FROM users;")

-- The json() function is a built-in helper
if rows then
  return json(rows)
else
  -- Handle errors
  return "Error querying database."
end
```

---

## Security

### Sandboxing (`--sandbox`)
The `--sandbox` flag provides a critical security layer for your Lua scripts. It:
1.  **Disables Unsafe Libraries:** Removes `io`, `os`, `package`, and `debug` libraries to prevent filesystem access, command execution, and other potentially harmful operations.
2.  **Sets an Execution Timeout:** A Lua hook is installed that terminates any script running for too long, preventing denial-of-service from infinite loops.

**It is strongly recommended to use `--sandbox` in production if you are running any Lua code.**

### Concurrency (`--fork`)
For better stability and security, the `--fork` flag creates a new child process to handle each incoming request. This provides OS-level memory isolation, ensuring that a crash in one request handler won't bring down the entire server.
It's a simple and robust model for concurrency.

### TLS/HTTPS (`--tls`)
Macrobean supports TLS out-of-the-box.

**1. Generating Self-Signed Certificates (for Development)**
You can generate a local certificate and key using `openssl`:
```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=localhost"
```

### For admin/root privileges, check out [SECURITY.md](SECURITY.md)

**2. Running with TLS**
```bash
./macrobean.com --tls --cert cert.pem --key key.pem
```
The server will now be available at **https://localhost:8080**.

**3. Production Certificates**
For a public-facing website, use a trusted certificate authority like [Let's Encrypt](https://letsencrypt.org/).

---

## Technical Details
- **Lua:** ≥ 5.4
- **TLS:** mbedTLS ≥ 3.5.2  and < 4.0
- **Compatibility:** Built for both Linux and macOS. Supports all Apple Silicon (M1, M2, M3, etc.) and Intel-based Macs. Should run on most modern Linux distributions.

## Common Issues & Troubleshooting

- **"Permission denied"**
  - **Fix:** The binary needs execute permissions. Run `chmod +x macrobean.com`.

- **"macrobean.com is damaged and can’t be opened." (macOS)**
  - **Fix:** This is macOS Gatekeeper. Remove the quarantine attribute: `xattr -d com.apple.quarantine macrobean.com`.

- **TLS Certificate Errors**
  - **Fix:** Ensure the paths passed to `--cert` and `--key` are correct and that the files are valid PEM-encoded certificates. Use `openssl x509 -in cert.pem -text -noout` to validate.

- **Static files (CSS, images) are not loading or appear broken.**
  - **Fix:** This almost always means your `site.zip` was created without the `-0` (store-only) flag. Macrobean cannot read compressed files. Re-create your ZIP archive correctly.

- **Code Signing (Optional)**
  - For simple distribution, code signing is not required. If you intend to distribute Macrobean as part of a larger `.app` bundle on macOS, you may need to sign it. You can use a self-signed certificate for development:
    ```bash
    codesign -s "-" --force --timestamp=none ./macrobean.com
    ```

---

## API Examples
Assuming the server is running in dev mode (`./macrobean.com --dev --lua --db --zip site.zip`):

```bash
# Serve a static file
curl http://localhost:8080/index.html

# Execute a simple Lua script
# site/hello.lua: return "Hello from Lua!"
curl http://localhost:8080/hello.lua
# Returns: Hello from Lua!

# Call a dynamic route with a query parameter
# init.lua: routes["/greet"] = function() return "Hi, " .. request.query.name end
curl "http://localhost:8080/greet?name=developer"
# Returns: Hi, developer

# Query the SQLite database
curl http://localhost:8080/query.lua
# Returns: [{"id":"1","name":"Alice"},{"id":"2","name":"Bob"}]
```

## Contributing
This project is open-source under the terms of The Unlicense License. Contributions, issues, and feature requests are welcome. Please check [CONTRIBUTION](CONTRIBUTING.md) for more information.

---

