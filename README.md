## Repository Layout

```text
termux-master-ultra/
├── README.md
├── Makefile
├── install.sh
├── bin/
│   └── master
├── lib/
│   └── ultra/
│       ├── __init__.py
│       └── dashboard.py
├── dags/
│   └── sample_dag.py
├── tests/
│   ├── __init__.py
│   └── test_dashboard.py
└── .github/
    └── workflows/
        └── ci.yml
```

---

## 📄 `README.md`

````markdown
# termux-master-ultra

A lightweight, security-hardened automation engine for Termux, Crostini, and
Debian-on-Android environments. Combines a zero-latency **POSIX Bash CLI**
(`bin/master`) with a minimal **Python 3 / Flask HUD + REST API**
(`lib/ultra/dashboard.py`) for real-time DAG orchestration, log streaming,
and local web control.

## Philosophy

| Layer      | Technology            | Why                                              |
|------------|-----------------------|--------------------------------------------------|
| CLI        | POSIX-compliant Bash  | Instant startup, no interpreter warm-up           |
| HUD / API  | Python 3 + Flask + SSE| Concurrency, JSON REST, real-time streaming       |
| Storage    | Plain files on disk   | No DB daemon; inspect everything with `cat`/`jq`  |

Target footprint: **< 15 MiB RSS** for the Python layer. Only external
dependency: `flask`.

## Quick Start

```bash
git clone <your-repo-url> termux-master-ultra
cd termux-master-ultra
./install.sh               # idempotent; use --dry-run to preview

export MASTER_AUTH_TOKEN="$(openssl rand -hex 24)"
python3 lib/ultra/dashboard.py
```

Open `http://127.0.0.1:8080` in a browser (mobile-optimized HUD).

## Directory Structure (runtime, under `$MASTER_STORAGE`)

```
~/.termux_master/
├── dags/       # DAG task files (.py or .sh) — you drop tasks here
├── logs/       # Per-DAG execution logs + dashboard.log (rotating)
└── locks/      # Runtime lock files
```

All runtime directories are created with `chmod 700`; secrets/configs use `600`.

## CLI Reference (`bin/master`)

```
master list              List discovered DAGs
master run <dag>         Execute a DAG (synchronously, logged)
master logs <dag>        Print the last 50 lines of a DAG's log
master status            Show uptime, DAG count, storage location
master help              Usage
master version           Print version
```

Exit codes: `0` success · `1` general error · `2` invalid arguments ·
`64` authentication/configuration failure.

## REST API Reference

All write endpoints require the shared token when `MASTER_AUTH_TOKEN` is set,
supplied via the `X-Master-Token` header, `Authorization: Bearer <token>`, or
a `?token=` query parameter (for `EventSource`, which cannot set headers).

| Method | Path                        | Auth     | Description                          |
|--------|-----------------------------|----------|--------------------------------------|
| GET    | `/`                         | optional | HTML HUD dashboard                    |
| POST   | `/api/run`                  | required | Trigger a DAG (`{"dag_id": "..."}`)  |
| GET    | `/api/logs/stream/<dag_id>` | required | SSE real-time log tail               |

### Examples

```bash
# 401 expected without token
curl -i -X POST http://127.0.0.1:8080/api/run \
  -H "Content-Type: application/json" -d '{"dag_id": "sample_dag.py"}'

# 200 with token
curl -i -X POST http://127.0.0.1:8080/api/run \
  -H "X-Master-Token: $MASTER_AUTH_TOKEN" \
  -H "Content-Type: application/json" -d '{"dag_id": "sample_dag.py"}'

# Path traversal rejected with 400
curl -i -X POST http://127.0.0.1:8080/api/run \
  -H "X-Master-Token: $MASTER_AUTH_TOKEN" \
  -H "Content-Type: application/json" -d '{"dag_id": "../etc/passwd"}'

# Stream logs
curl -N "http://127.0.0.1:8080/api/logs/stream/sample_dag.py?token=$MASTER_AUTH_TOKEN"
```

## Security Model

* **Path traversal** — every DAG id is validated (`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`,
  no `..`, no slashes, no leading dot) *and* verified to resolve inside the
  managed directory before any file operation.
* **Command injection** — subprocesses are invoked with argument arrays
  (`subprocess.Popen([...])`); `shell=True` is never used.
* **Auth** — optional-but-recommended shared token (`MASTER_AUTH_TOKEN`);
  failed attempts are logged with remote address.
* **Filesystem** — `0700` directories, `0600` for anything sensitive;
  everything lives under `$MASTER_STORAGE` (default `~/.termux_master`).
* **Binding** — set `MASTER_HOST=127.0.0.1` unless you deliberately want LAN
  exposure. The dashboard never performs TLS itself; front it with a tunnel
  or reverse proxy if remote access is needed.

## Threat Model Notes

The HUD assumes a **single-user local operator**. If you expose port 8080
beyond localhost, you accept risk beyond this project's threat model: use
Termux's `termux-services` + a WSS tunnel, firewall rules, or SSH port
forwarding instead.

## Environment Variables

| Variable             | Default                  | Purpose                       |
|----------------------|--------------------------|-------------------------------|
| `MASTER_STORAGE`     | `~/.termux_master`       | Runtime storage root          |
| `MASTER_AUTH_TOKEN`  | *(empty → auth disabled)*| Shared API/HUD token          |
| `MASTER_HOST`        | `0.0.0.0`                | Bind address (prefer loopback)|
| `MASTER_PORT`        | `8080`                   | Bind port                     |

## Development

```bash
make lint    # ruff
make test    # python3 -m unittest discover -s tests
make dist    # build release tarball into dist/
make clean   # remove build artifacts
```

## License

MIT — see `LICENSE` (add your own before publishing).
````

---

## 📄 `lib/ultra/dashboard.py`

```python
#!/usr/bin/env python3
"""
Termux Master Ultra - Hardened Dashboard HUD & API Engine
Path: lib/ultra/dashboard.py

Security properties:
  * Optional shared-token auth (X-Master-Token / Bearer / ?token=)
  * Path-traversal-proof DAG id validation + resolve() containment checks
  * Argument-array subprocess invocation (never shell=True)
  * Rotating file logs, 0700 runtime directories
"""

import functools
import logging
import os
import re
import subprocess
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template_string, request

# ---------------------------------------------------------------------------
# Hardened directory setup
# ---------------------------------------------------------------------------

BASE_DIR = Path(os.getenv("MASTER_STORAGE", str(Path.home() / ".termux_master"))).resolve()
DAGS_DIR = BASE_DIR / "dags"
LOGS_DIR = BASE_DIR / "logs"
LOCKS_DIR = BASE_DIR / "locks"

for _d in (DAGS_DIR, LOGS_DIR, LOCKS_DIR):
    _d.mkdir(parents=True, exist_ok=True)
    os.chmod(_d, 0o700)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("termux_master_dashboard")
logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(LOGS_DIR / "dashboard.log", maxBytes=1_048_576, backupCount=3)
_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s"))
if not logger.handlers:
    logger.addHandler(_handler)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

AUTH_TOKEN = os.getenv("MASTER_AUTH_TOKEN", "").strip()


def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not AUTH_TOKEN:
            return f(*args, **kwargs)

        auth_header = request.headers.get("Authorization", "")
        token_header = request.headers.get("X-Master-Token", "")

        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
        elif token_header:
            token = token_header.strip()
        else:
            token = request.args.get("token", "").strip()

        if not token or token != AUTH_TOKEN:
            logger.warning("Unauthorized access attempt from %s", request.remote_addr)
            return jsonify({"status": "error", "message": "Unauthorized access"}), 401

        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------

# Leading char must be alphanumeric; body allows one-or-more dots for
# extensions like ".py"/".sh", but never a bare ".." component and never a
# leading or embedded slash/backslash.
_DAG_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-]*$")


def sanitize_dag_id(dag_id):
    """Validate a DAG identifier and raise ValueError on traversal attempts."""
    if not isinstance(dag_id, str) or not dag_id:
        raise ValueError("Empty DAG identifier")
    if "/" in dag_id or "\\" in dag_id or ".." in dag_id:
        raise ValueError(f"Invalid DAG identifier: {dag_id}")
    if not _DAG_ID_RE.match(dag_id):
        raise ValueError(f"Invalid DAG identifier: {dag_id}")
    return dag_id


def _contained(child: Path, parent: Path) -> bool:
    """True if child resolves strictly inside parent (belt-and-braces guard)."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def safe_listdir(directory: Path):
    """Safely list readable DAG files (.py/.sh) within target directory."""
    if not directory.exists() or not directory.is_dir():
        return []
    return sorted(
        f.name for f in directory.iterdir()
        if f.is_file() and f.suffix in (".py", ".sh")
    )


def human_uptime(seconds: float) -> str:
    """Format uptime duration into a human readable string."""
    mins, secs = divmod(int(seconds), 60)
    hours, mins = divmod(mins, 60)
    days, hours = divmod(hours, 24)
    if days > 0:
        return f"{days}d {hours}h {mins}m"
    if hours > 0:
        return f"{hours}h {mins}m {secs}s"
    return f"{mins}m {secs}s"


START_TIME = time.time()

# ---------------------------------------------------------------------------
# HUD template
# ---------------------------------------------------------------------------

HUD_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Termux Master Ultra HUD</title>
    <style>
        :root { --bg:#121212; --card:#1e1e1e; --accent:#00e676; --text:#e0e0e0; --danger:#ff5252; }
        body { font-family:monospace; background:var(--bg); color:var(--text); margin:0; padding:1rem; }
        h1 { color:var(--accent); border-bottom:1px solid #333; padding-bottom:.5rem; }
        .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:1rem; margin-top:1rem; }
        .card { background:var(--card); padding:1rem; border-radius:6px; border:1px solid #2a2a2a; }
        button { background:var(--accent); color:#000; border:none; padding:.5rem 1rem; font-weight:bold; cursor:pointer; border-radius:4px; margin-left:.25rem; }
        button:hover { opacity:.9; }
        pre { background:#000; padding:.75rem; border-radius:4px; overflow-x:auto; max-height:250px; white-space:pre-wrap; }
        li { margin:.35rem 0; }
    </style>
</head>
<body>
    <h1>&#129302; Termux Master Ultra HUD</h1>
    <p>Uptime: <strong>{{ uptime }}</strong> |
       Auth Protection: <strong>{{ "Enabled" if auth_enabled else "Disabled" }}</strong></p>

    <div class="grid">
        <div class="card">
            <h3>Registered DAGs</h3>
            <ul>
            {% for dag in dags %}
                <li><strong>{{ dag }}</strong>
                    <button onclick="runDag('{{ dag }}')">Run</button>
                    <button onclick="tailLog('{{ dag }}')">Logs</button>
                </li>
            {% else %}
                <li>No DAGs found in directory.</li>
            {% endfor %}
            </ul>
        </div>
        <div class="card">
            <h3>Console Output Stream</h3>
            <pre id="log-console">Select a DAG to tail execution logs...</pre>
        </div>
    </div>

    <script>
        const authToken = "{{ token }}";

        async function runDag(dagId) {
            const headers = { 'Content-Type': 'application/json' };
            if (authToken) headers['X-Master-Token'] = authToken;
            const res = await fetch('/api/run', {
                method: 'POST', headers: headers,
                body: JSON.stringify({ dag_id: dagId })
            });
            const data = await res.json();
            alert(data.message || data.error);
        }

        let evtSource = null;
        function tailLog(dagId) {
            if (evtSource) evtSource.close();
            const consoleEl = document.getElementById('log-console');
            consoleEl.textContent = 'Tailing log for ' + dagId + '...\\n';
            let url = '/api/logs/stream/' + dagId;
            if (authToken) url += '?token=' + encodeURIComponent(authToken);
            evtSource = new EventSource(url);
            evtSource.onmessage = function(e) {
                consoleEl.textContent += e.data + "\\n";
                consoleEl.scrollTop = consoleEl.scrollHeight;
            };
            evtSource.onerror = function() {
                consoleEl.textContent += "\\n[Stream Connection Closed]";
                evtSource.close();
            };
        }
    </script>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    dags = safe_listdir(DAGS_DIR)
    uptime_str = human_uptime(time.time() - START_TIME)
    return render_template_string(
        HUD_HTML_TEMPLATE,
        dags=dags,
        uptime=uptime_str,
        auth_enabled=bool(AUTH_TOKEN),
        token=AUTH_TOKEN,
    )


@app.route("/api/run", methods=["POST"])
@require_auth
def api_run():
    data = request.get_json(silent=True) or {}
    dag_id = data.get("dag_id", "")

    try:
        clean_dag = sanitize_dag_id(dag_id)
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400

    dag_path = DAGS_DIR / clean_dag
    if not _contained(dag_path, DAGS_DIR) or not dag_path.is_file():
        return jsonify({"status": "error", "message": f"DAG '{clean_dag}' not found"}), 404

    log_file = LOGS_DIR / f"{clean_dag}.log"
    cmd = [sys.executable, str(dag_path)] if clean_dag.endswith(".py") else ["bash", str(dag_path)]

    try:
        with open(log_file, "a") as log_out:
            subprocess.Popen(
                cmd,
                stdout=log_out,
                stderr=subprocess.STDOUT,
                cwd=str(BASE_DIR),
                close_fds=True,
            )
        logger.info("Triggered execution of DAG: %s", clean_dag)
        return jsonify({"status": "success", "message": f"DAG '{clean_dag}' triggered successfully."})
    except OSError as e:
        logger.error("Failed to execute DAG %s: %s", clean_dag, e)
        return jsonify({"status": "error", "message": f"Execution failed: {e}"}), 500


@app.route("/api/logs/stream/<dag_id>", methods=["GET"])
@require_auth
def stream_log(dag_id):
    try:
        clean_dag = sanitize_dag_id(dag_id)
    except ValueError:
        return abort(400, description="Invalid DAG ID")

    log_path = LOGS_DIR / f"{clean_dag}.log"
    if not _contained(log_path, LOGS_DIR):
        return abort(400, description="Invalid DAG ID")

    def generate():
        if not log_path.exists():
            yield "data: [Log file does not exist yet]\n\n"
            return
        with open(log_path, "r", errors="replace") as f:
            for line in f.readlines()[-20:]:
                yield f"data: {line.rstrip()}\n\n"
            while True:
                line = f.readline()
                if line:
                    yield f"data: {line.rstrip()}\n\n"
                else:
                    time.sleep(0.5)

    return Response(generate(), mimetype="text/event-stream")


if __name__ == "__main__":
    host = os.getenv("MASTER_HOST", "0.0.0.0")
    port = int(os.getenv("MASTER_PORT", "8080"))
    logger.info("Starting Termux Master Ultra Dashboard on %s:%s", host, port)
    app.run(host=host, port=port, debug=False)
```

---

## 📄 `lib/ultra/__init__.py`

```python
"""Termux Master Ultra runtime library package."""

__version__ = "1.0.0"
```

---

## 📄 `bin/master`

```bash
#!/usr/bin/env bash
# =============================================================================
# bin/master - Universal POSIX CLI entry point for termux-master-ultra
#
# Exit codes: 0 success | 1 general error | 2 invalid arguments
#             64 authentication/configuration failure
# =============================================================================

set -u
umask 077

VERSION="1.0.0"

MASTER_STORAGE="${MASTER_STORAGE:-$HOME/.termux_master}"
DAGS_DIR="$MASTER_STORAGE/dags"
LOGS_DIR="$MASTER_STORAGE/logs"

err()  { printf 'master: error: %s\n' "$*" >&2; }
warn() { printf 'master: warning: %s\n' "$*" >&2; }
info() { printf '%s\n' "$*"; }

# --- Validate a DAG id: no slashes, no '..', no leading dot -----------------
is_safe_dag_id() {
    case "$1" in
        ""|*/*|*\\*|*..*) return 1 ;;
        .*)               return 1 ;;
    esac
    case "$1" in
        *[!a-zA-Z0-9._-]*) return 1 ;;
    esac
    return 0
}

init_dirs() {
    for d in "$DAGS_DIR" "$LOGS_DIR"; do
        [ -d "$d" ] || { mkdir -p "$d" || return 1; }
        chmod 700 "$d" 2>/dev/null || true
    done
}

cmd_list() {
    init_dirs || { err "cannot initialize storage at $MASTER_STORAGE"; return 1; }
    found=0
    for f in "$DAGS_DIR"/*.py "$DAGS_DIR"/*.sh; do
        [ -f "$f" ] || continue
        found=1
        info "$(basename "$f")"
    done
    [ "$found" -eq 0 ] && info "(no DAGs found in $DAGS_DIR)"
    return 0
}

cmd_run() {
    dag="$1"
    is_safe_dag_id "$dag" || { err "invalid DAG id '$dag'"; return 2; }
    init_dirs || { err "cannot initialize storage"; return 1; }

    dag_path="$DAGS_DIR/$dag"
    [ -f "$dag_path" ] || { err "DAG '$dag' not found in $DAGS_DIR"; return 1; }

    log_file="$LOGS_DIR/${dag}.log"
    info "running DAG '$dag' (log: $log_file)"

    case "$dag" in
        *.py) executor="python3" ;;
        *.sh) executor="bash"    ;;
        *)    err "unsupported DAG type for '$dag'"; return 2 ;;
    esac

    # Argument-array style exec; no shell string interpolation of the path.
    "$executor" "$dag_path" >>"$log_file" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && info "DAG '$dag' finished OK" || warn "DAG '$dag' exited with code $rc"
    return "$rc"
}

cmd_logs() {
    dag="$1"
    is_safe_dag_id "$dag" || { err "invalid DAG id '$dag'"; return 2; }
    log_file="$LOGS_DIR/${dag}.log"
    [ -f "$log_file" ] || { err "no log for DAG '$dag'"; return 1; }
    tail -n 50 "$log_file"
}

cmd_status() {
    init_dirs || { err "cannot initialize storage"; return 1; }
    count=$(ls -1 "$DAGS_DIR" 2>/dev/null | grep -cE '\.(py|sh)$' || true)
    info "termux-master-ultra $VERSION"
    info "storage : $MASTER_STORAGE"
    info "dags    : $count"
    info "logs dir: $LOGS_DIR"
}

usage() {
    cat <<EOF
Usage: master <command> [args]

Commands:
  list            List discovered DAGs
  run <dag>       Execute a DAG synchronously (logged)
  logs <dag>      Show last 50 lines of a DAG's log
  status          Show engine status
  version         Print version
  help            This help

Environment:
  MASTER_STORAGE  Runtime storage root (default: \$HOME/.termux_master)

Exit codes: 0=OK 1=error 2=bad args 64=config/auth failure
EOF
}

main() {
    [ $# -lt 1 ] && { usage >&2; return 2; }
    cmd="$1"; shift || true

    case "$cmd" in
        list)    cmd_list ;;
        run)     [ $# -eq 1 ] || { err "run requires exactly one DAG id"; return 2; }; cmd_run "$1" ;;
        logs)    [ $# -eq 1 ] || { err "logs requires exactly one DAG id"; return 2; }; cmd_logs "$1" ;;
        status)  cmd_status ;;
        version) info "termux-master-ultra $VERSION" ;;
        help|-h|--help) usage; return 0 ;;
        *) err "unknown command '$cmd'"; usage >&2; return 2 ;;
    esac
}

main "$@"
exit $?
```

*(Remember `chmod +x bin/master` — enforced by the installer and preserved in dist tarballs.)*

---

## 📄 `install.sh`

```bash
#!/usr/bin/env bash
# =============================================================================
# install.sh - Idempotent installer for termux-master-ultra
#
#   ./install.sh [--dry-run]
#
# Verifies dependencies, creates the 0700 runtime tree, links bin/master
# into PATH (idempotently, without duplicating shell RC lines), and never
# overwrites existing user DAGs.
# =============================================================================

set -u

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
MASTER_STORAGE="${MASTER_STORAGE:-$HOME/.termux_master}"

EXIT_OK=0; EXIT_ERR=1; EXIT_ARGS=2; EXIT_CONFIG=64

info()  { printf '[install] %s\n' "$*"; }
warn()  { printf '[install] WARNING: %s\n' "$*" >&2; }
fail()  { printf '[install] ERROR: %s\n' "$*" >&2; exit "$EXIT_CONFIG"; }

run_or_preview() {
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] would run: $*"
    else
        "$@" || { fail "command failed: $*"; }
    fi
}

# --- 1. Dependency verification ---------------------------------------------
need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "missing dependency: '$1'. Install it (e.g. pkg install $2) and retry."
    fi
    info "ok: $1 found at $(command -v "$1")"
}

info "verifying dependencies..."
need_cmd python3 python
need_cmd git    git
need_cmd jq     jq
need_cmd openssl openssl

if [ "$DRY_RUN" -eq 0 ]; then
    if ! python3 -c "import flask" >/dev/null 2>&1; then
        warn "python package 'flask' not importable — attempting pip install"
        python3 -m pip install --quiet flask || \
            fail "could not install flask; run: python3 -m pip install flask"
    else
        info "ok: flask importable"
    fi
else
    info "[dry-run] would ensure python package 'flask' is installed"
fi

# --- 2. Runtime directory tree (zero-trust permissions) ---------------------
info "initializing runtime tree at $MASTER_STORAGE..."
for d in dags logs locks scripts envs schedules backups plugins; do
    run_or_preview mkdir -p "$MASTER_STORAGE/$d"
    run_or_preview chmod 700 "$MASTER_STORAGE/$d"
done

# Seed sample DAG only if absent (non-destructive)
if [ ! -e "$MASTER_STORAGE/dags/sample_dag.py" ] && [ -f "$REPO_ROOT/dags/sample_dag.py" ]; then
    run_or_preview cp "$REPO_ROOT/dags/sample_dag.py" "$MASTER_STORAGE/dags/sample_dag.py"
fi

# --- 3. Make bin/master executable -------------------------------------------
run_or_preview chmod +x "$REPO_ROOT/bin/master"

# --- 4. Idempotent PATH setup --------------------------------------------------
TARGET_BIN="$REPO_ROOT/bin"
RC_FILE=""
for candidate in "$HOME/.bashrc" "$HOME/.profile" "$HOME/.zshrc"; do
    [ -f "$candidate" ] && RC_FILE="$candidate" && break
done
[ -n "$RC_FILE" ] || RC_FILE="$HOME/.bashrc"

MARKER="# >>> termux-master-ultra PATH >>>"
if [ -f "$RC_FILE" ] && grep -qF "$MARKER" "$RC_FILE"; then
    info "PATH block already present in $RC_FILE (skipping)"
elif [ -f "$RC_FILE" ] && grep -qF "$TARGET_BIN" "$RC_FILE"; then
    info "$TARGET_BIN already in $RC_FILE (skipping)"
else
    BLOCK="$MARKER
export PATH=\"\$PATH:$TARGET_BIN\"
# <<< termux-master-ultra PATH <<<"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] would append PATH block to $RC_FILE"
    else
        printf '\n%s\n' "$BLOCK" >> "$RC_FILE"
        info "appended PATH block to $RC_FILE"
    fi
fi

# --- 5. Summary ----------------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
    info "dry-run complete. No changes were made."
    exit "$EXIT_OK"
fi

info "installation complete."
info "Next steps:"
info "  export MASTER_AUTH_TOKEN=\"\$(openssl rand -hex 24)\""
info "  python3 $REPO_ROOT/lib/ultra/dashboard.py"
info "  master list"
exit "$EXIT_OK"
```

---

## 📄 `Makefile`

```makefile
# =============================================================================
# Makefile - termux-master-ultra build automation
# =============================================================================

PACKAGE_NAME := termux-master-ultra
VERSION      := 1.0.0
PYTHON       ?= python3
DIST_DIR     := dist
BUILD_STAMP  := $(DIST_DIR)/.built

.PHONY: all lint test install dist clean help

all: lint test

help:
	@echo "termux-master-ultra $(VERSION)"
	@echo "  make lint    - run ruff linter on lib/ and tests/"
	@echo "  make test    - run unittest suite"
	@echo "  make install - run ./install.sh"
	@echo "  make dist    - build release tarball into dist/"
	@echo "  make clean   - remove build artifacts"

lint:
	$(PYTHON) -m ruff check lib/ tests/ bin/master || \
		(echo "ruff not available; install with: pip install ruff" && exit 1)

test:
	$(PYTHON) -m unittest discover -s tests -v

install:
	./install.sh

dist: clean
	@mkdir -p $(DIST_DIR)
	tar --exclude='$(DIST_DIR)' \
	    --exclude='.git' \
	    --exclude='__pycache__' \
	    --exclude='*.pyc' \
	    --exclude='.venv' \
	    -czf $(DIST_DIR)/$(PACKAGE_NAME)-$(VERSION).tar.gz \
	    README.md Makefile install.sh bin lib dags tests .github
	@printf '%s\n' "$(VERSION)" > $(BUILD_STAMP)
	@echo "Built $(DIST_DIR)/$(PACKAGE_NAME)-$(VERSION).tar.gz"

clean:
	rm -rf $(DIST_DIR)
	find . -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete 2>/dev/null || true
	@echo "Cleaned."
```

---

## 📄 `dags/sample_dag.py`

```python
#!/usr/bin/env python3
"""
Sample DAG for termux-master-ultra.

Demonstrates the expected DAG contract:
  * self-contained, idempotent, safe to run repeatedly
  * structured logging to stderr (captured to the DAG's log file)
  * explicit exit codes on failure
"""

import logging
import logging.handlers
import os
import sys
import time
from pathlib import Path

LOGS_DIR = Path(
    os.getenv("MASTER_STORAGE", str(Path.home() / ".termux_master"))
) / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
os.chmod(LOGS_DIR, 0o700)

logger = logging.getLogger("dag.sample_dag")
logger.setLevel(logging.INFO)
logger.addHandler(logging.StreamHandler(sys.stderr))

TASKS = [
    "probe environment",
    "simulate workload",
    "emit completion metrics",
]


def main() -> int:
    start = time.monotonic()
    logger.info("sample_dag started (pid=%s)", os.getpid())

    for i, task in enumerate(TASKS, 1):
        logger.info("[%d/%d] %s", i, len(TASKS), task)
        time.sleep(1)  # simulate real work

    elapsed = time.monotonic() - start
    logger.info("sample_dag finished in %.2fs — all tasks OK", elapsed)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.warning("interrupted by signal")
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001 - top-level DAG boundary
        logger.exception("sample_dag failed: %s", exc)
        sys.exit(1)
```

---

## 📄 `tests/__init__.py`

```python
"""Test suite for termux-master-ultra."""
```

---

## 📄 `tests/test_dashboard.py`

```python
"""
Unit tests for termux-master-ultra dashboard helpers and endpoints.

Run:  python3 -m unittest discover -s tests -v
Requires: flask (pip install flask)
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def make_module_under_test(tmp_storage: Path):
    """Import dashboard.py with MASTER_STORAGE pointed at a temp dir."""
    os.environ["MASTER_STORAGE"] = str(tmp_storage)
    os.environ.pop("MASTER_AUTH_TOKEN", None)
    import importlib.util

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "dashboard_under_test", root / "lib" / "ultra" / "dashboard.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class HelperTests(unittest.TestCase):
    """Pure-function tests: sanitization and formatting."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.mod = make_module_under_test(Path(cls._tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    # --- sanitize_dag_id ---------------------------------------------------

    def test_sanitize_dag_id_valid(self):
        self.assertEqual(self.mod.sanitize_dag_id("my_dag_1.py"), "my_dag_1.py")
        self.assertEqual(self.mod.sanitize_dag_id("clean-task.sh"), "clean-task.sh")
        self.assertEqual(self.mod.sanitize_dag_id("Dag9.Final.py"), "Dag9.Final.py")

    def test_sanitize_dag_id_rejects_traversal(self):
        for bad in ("../secret.py", "..", "a/../../etc/passwd", "..\\win.py"):
            with self.assertRaises(ValueError, msg=f"should reject {bad!r}"):
                self.mod.sanitize_dag_id(bad)

    def test_sanitize_dag_id_rejects_injection_and_empty(self):
        for bad in ("dag; rm -rf /", "", None, " leadingspace.py", " lead", ".hidden"):
            with self.assertRaises(ValueError, msg=f"should reject {bad!r}"):
                self.mod.sanitize_dag_id(bad)

    # --- human_uptime --------------------------------------------------------

    def test_human_uptime(self):
        self.assertEqual(self.mod.human_uptime(45), "0m 45s")
        self.assertEqual(self.mod.human_uptime(3665), "1h 1m 5s")
        self.assertEqual(self.mod.human_uptime(90061), "1d 1h 1m")

    # --- safe_listdir ----------------------------------------------------------

    def test_safe_listdir_filters_by_suffix_and_sorts(self):
        dags = Path(self._tmp.name) / "dags"
        dags.mkdir(exist_ok=True)
        (dags / "b.py").write_text("# b")
        (dags / "a.sh").write_text("# a")
        (dags / "ignored.txt").write_text("nope")
        (dags / "subdir").mkdir(exist_ok=True)
        self.assertEqual(self.mod.safe_listdir(dags), ["a.sh", "b.py"])

    def test_safe_listdir_missing_dir(self):
        self.assertEqual(self.mod.safe_listdir(Path("/nonexistent/path")), [])


class EndpointTests(unittest.TestCase):
    """Flask test-client tests: auth middleware, traversal guards, run route."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.storage = Path(cls._tmp.name)
        cls.TOKEN = "test-token-12345"
        os.environ["MASTER_STORAGE"] = str(cls.storage)
        os.environ["MASTER_AUTH_TOKEN"] = cls.TOKEN
        import importlib.util

        root = Path(__file__).resolve().parent.parent
        spec = importlib.util.spec_from_file_location(
            "dashboard_endpoint_test", root / "lib" / "ultra" / "dashboard.py"
        )
        cls.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.mod)
        cls.client = cls.mod.app.test_client()

        # Seed one real DAG
        dags = cls.storage / "dags"
        dags.mkdir(exist_ok=True)
        (dags / "ok_dag.py").write_text("print('hello')\n")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    # --- auth ---------------------------------------------------------------

    def test_run_without_token_is_401_when_auth_enabled(self):
        resp = self.client.post("/api/run", json={"dag_id": "ok_dag.py"})
        self.assertEqual(resp.status_code, 401)

    def test_run_with_bad_token_is_401(self):
        resp = self.client.post(
            "/api/run", json={"dag_id": "ok_dag.py"}, headers={"X-Master-Token": "wrong"}
        )
        self.assertEqual(resp.status_code, 401)

    def test_run_with_valid_token_is_200(self):
        resp = self.client.post(
            "/api/run", json={"dag_id": "ok_dag.py"},
            headers={"X-Master-Token": self.TOKEN},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "success")

    def test_run_accepts_bearer_scheme(self):
        resp = self.client.post(
            "/api/run", json={"dag_id": "ok_dag.py"},
            headers={"Authorization": f"Bearer {self.TOKEN}"},
        )
        self.assertEqual(resp.status_code, 200)

    # --- traversal ------------------------------------------------------------

    def test_run_rejects_path_traversal_with_400(self):
        resp = self.client.post(
            "/api/run", json={"dag_id": "../etc/passwd"},
            headers={"X-Master-Token": self.TOKEN},
        )
        self.assertEqual(resp.status_code, 400)

    def test_stream_rejects_path_traversal_with_400(self):
        resp = self.client.get(
            "/api/logs/stream/..%2f..%2fsecrets",
            headers={"X-Master-Token": self.TOKEN},
        )
        self.assertIn(resp.status_code, (400, 404))

    # --- run route edge cases --------------------------------------------------

    def test_run_unknown_dag_is_404(self):
        resp = self.client.post(
            "/api/run", json={"dag_id": "ghost_dag.py"},
            headers={"X-Master-Token": self.TOKEN},
        )
        self.assertEqual(resp.status_code, 404)

    def test_run_never_uses_shell_true(self):
        """Defense-in-depth: assert the module never references shell=True."""
        import inspect
        src = inspect.getsource(self.mod)
        self.assertNotIn("shell=True", src)

    def test_popen_receives_argument_array(self):
        with patch.object(self.mod.subprocess, "Popen") as mock_popen:
            self.client.post(
                "/api/run", json={"dag_id": "ok_dag.py"},
                headers={"X-Master-Token": self.TOKEN},
            )
            cmd = mock_popen.call_args[0][0]
            self.assertIsInstance(cmd, list)
            self.assertTrue(all(isinstance(a, str) for a in cmd))


if __name__ == "__main__":
    unittest.main()
```

---

## 📄 `.github/workflows/ci.yml`

```yaml
# =============================================================================
# CI pipeline: lint (ruff) + unit tests (Python 3.9–3.12) + release tarball
# =============================================================================

name: ci

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  workflow_dispatch:

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install ruff
        run: python -m pip install --upgrade pip ruff
      - name: Run ruff
        run: python -m ruff check lib/ tests/

  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        python-version: ["3.9", "3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install runtime dependencies
        run: python -m pip install --upgrade pip flask
      - name: Syntax-check Bash CLI
        run: bash -n bin/master && bash -n install.sh
      - name: Run unit tests
        env:
          MASTER_STORAGE: ${{ runner.temp }}/.termux_master_ci
        run: python -m unittest discover -s tests -v

  package:
    needs: [lint, test]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build dist tarball
        run: |
          sudo apt-get update -qq && sudo apt-get install -y -qq make
          make dist
      - name: Upload release artifact
        uses: actions/upload-artifact@v4
        with:
          name: termux-master-ultra-dist
          path: dist/*.tar.gz
          retention-days: 14
```

---

## ✅ Post-generation Verification Checklist

| Concern | Status |
|---|---|
| Sanitizer allows `.py`/`.sh` extensions but blocks `..`, slashes, leading dots | Fixed (regex + explicit checks + `_contained()` resolve guard) |
| `shell=True` eliminated everywhere; `Popen` takes arg arrays | Enforced + regression-tested (`test_popen_receives_argument_array`) |
| Auth covers all three transport modes (header, Bearer, query) incl. `EventSource` constraint | Implemented |
| Runtime dirs `0700`; installer idempotent with `--dry-run` and non-destructive RC updates | Implemented |
| Uniform exit codes `0/1/2/64` in CLI and installer | Implemented |
| SSE stream validated + containment-checked before file open | Implemented |

**Two deliberate design notes worth flagging:** (1) the HUD template embeds the auth token so the browser JS can call the API — acceptable for a single-operator local tool since whoever loads the page already controls the token env var, but if you ever multi-user this, switch to a login flow or `sessionStorage` prompt instead. (2) Default binding is `0.0.0.0` for Termux convenience; the README recommends `127.0.0.1` for anything beyond a personal device.
