#!/usr/bin/env python3
"""Generic bootstrap for OSC scheduled jobs (My Jobs).

Fetches a source tarball (for example a private GitHub repo via the API
tarball endpoint), unpacks it, optionally installs dependencies, and runs a
configured list of commands inside the unpacked tree. All behavior is driven
by environment variables, which on OSC are injected from the parameter store
bound to the job, so one job definition can be re-pointed between runs
without recreating the job.

Optional command-line pin (lives in the job's worker command, a DIFFERENT
trust domain than the parameter store):

  python bootstrap.py --require-repo OWNER/REPO
      Refuse any tarball URL that is not the GitHub API tarball endpoint of
      exactly that repository. Parameter-store writers cannot loosen this.

Environment contract (values typically come from an OSC parameter store):

  BOOTSTRAP_REQUIRE_REPO Same pin as --require-repo, read from the
                         environment when no CLI pin is given. NOTE: this
                         variant lives in the parameter store's trust
                         domain, so store writers CAN change it; prefer the
                         CLI pin where the platform delivers the worker
                         command.
  BOOTSTRAP_MODE         "probe" (default) or "run".
                         probe: print python/pip versions and the NAMES of
                         all environment variables (never values), then exit
                         0. Use it to verify that the parameter-store
                         binding actually injects into job runs.
  BOOTSTRAP_TARBALL_URL  run mode only, required. HTTPS URL of a .tar.gz to
                         fetch, e.g.
                         https://api.github.com/repos/OWNER/REPO/tarball/REF
  BOOTSTRAP_TOKEN_VAR    Name of the env var that holds a bearer token for
                         the tarball request (default: GITHUB_READ_PAT).
                         If that variable is unset the request is sent
                         unauthenticated (public sources). The token is
                         removed from the environment after the fetch, so
                         pip and the steps never see it.
  BOOTSTRAP_PIP_ARGS     Optional arguments to "python -m pip install",
                         executed in the unpacked tree, e.g.
                         "-r requirements.txt". Empty/unset skips pip.
  BOOTSTRAP_STEPS_B64    Preferred over BOOTSTRAP_STEPS when the commands
                         contain characters that the platform may mangle in
                         env injection (&, *, $, ...): the same step list,
                         base64-encoded (UTF-8). Takes precedence over
                         BOOTSTRAP_STEPS when both are set.
  BOOTSTRAP_STEPS        run mode only, required. Commands to run inside the
                         unpacked tree, separated by newlines or " && ".
                         Each command is shlex-split and executed WITHOUT a
                         shell; the first nonzero exit stops the chain and
                         becomes this process's exit code. The " && "
                         separator is purely textual and cannot appear
                         inside quoted arguments; use newline separation
                         for such commands.
  BOOTSTRAP_STEP_TIMEOUT Per-step (and pip) timeout in seconds
                         (default 1800).
  BOOTSTRAP_RESOLVE_MASKED  Set to "auto" to resolve masked secrets: some
                         platforms inject encrypted parameters as the
                         literal mask "***" instead of decrypting them. In
                         auto mode the launcher fetches the decrypted
                         config from the parameter store's own read API
                         (GET {BOOTSTRAP_CONFIG_URL}/config with the
                         x-config-api-key header, plus Authorization:
                         Bearer $OSC_ACCESS_TOKEN when present) and
                         replaces ONLY the masked entries, in memory,
                         before the steps run. Values are never printed.
  BOOTSTRAP_CONFIG_URL   Base https URL of the parameter store (config
                         service) instance. Required in auto mode.
  BOOTSTRAP_CONFIG_KEY_VAR  Name of the env var holding the config API key
                         (default CONFIG_API_KEY). The variable is removed
                         from the environment after resolution.
  BOOTSTRAP_CONFIG_PATH  Read-endpoint path on the config service (default
                         /api/v1/config, the documented Application Config
                         Service list endpoint).

Security posture: no shell is ever invoked; environment VALUES are never
printed by the launcher; redirects are followed only to https URLs and the
Authorization header is dropped when a redirect changes host; tar members
with absolute paths, ".." components, or special types (devices, FIFOs) are
rejected.

Exit codes: 0 success, 2 configuration error, 3 fetch/unpack failure,
124 step or pip timeout, 127 command not found, otherwise the failing
step's exit code.
"""

import base64
import binascii
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_TOKEN_VAR = "GITHUB_READ_PAT"
FETCH_TIMEOUT_S = 300


def log(msg):
    print("[bootstrap] " + msg, flush=True)


def fail_config(msg):
    log("CONFIG ERROR: " + msg)
    sys.exit(2)


def fail_fetch(msg):
    log("FETCH ERROR: " + msg)
    sys.exit(3)


def redacted(url):
    s = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((s.scheme, s.hostname or "", s.path, "", ""))


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to https, and drop the Authorization header
    when the redirect changes host (GitHub's codeload Location is
    pre-authorized, so private tarballs keep working)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            if not new.full_url.startswith("https://"):
                fail_fetch("refusing redirect to non-https URL")
            old_host = urllib.parse.urlsplit(req.full_url).hostname
            new_host = urllib.parse.urlsplit(new.full_url).hostname
            if old_host != new_host:
                new.remove_header("Authorization")
        return new


def probe():
    log("mode=probe python=" + sys.version.split()[0])
    pip = subprocess.run(
        [sys.executable, "-m", "pip", "--version"],
        capture_output=True, text=True, check=False,
    )
    log("pip: " + (pip.stdout.strip() or pip.stderr.strip()))
    log("env var NAMES (%d total), values never printed:" % len(os.environ))
    for name in sorted(os.environ):
        print("  " + name, flush=True)
    masked = sorted(k for k, v in os.environ.items() if v == "***")
    if masked:
        log("masked (value is literal ***): " + ", ".join(masked))
    log("probe complete")


def fetch_tarball(url, token_var, dest_dir, require_repo):
    if not url.startswith("https://"):
        fail_config("BOOTSTRAP_TARBALL_URL must be https://")
    if "@" in urllib.parse.urlsplit(url).netloc:
        fail_config("BOOTSTRAP_TARBALL_URL must not contain userinfo credentials")
    if require_repo:
        prefix = "https://api.github.com/repos/%s/tarball/" % require_repo
        if not url.startswith(prefix):
            fail_config(
                "tarball URL does not match the --require-repo pin (%s)"
                % require_repo)
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", "osc-job-bootstrap")
    token = os.environ.get(token_var, "")
    if token:
        request.add_header("Authorization", "Bearer " + token)
        log("fetching tarball (authenticated via $%s): %s" % (token_var, redacted(url)))
    else:
        log("fetching tarball (unauthenticated, $%s unset): %s" % (token_var, redacted(url)))
    opener = urllib.request.build_opener(_SafeRedirectHandler)
    tar_path = os.path.join(dest_dir, "src.tar.gz")
    try:
        resp = opener.open(request, timeout=FETCH_TIMEOUT_S)
        try:
            with open(tar_path, "wb") as out:
                while True:
                    chunk = resp.read(1 << 20)
                    if not chunk:
                        break
                    out.write(chunk)
        finally:
            resp.close()
    except urllib.error.HTTPError as exc:
        # Never echo headers/body. Note: GitHub answers 404 (not 401/403)
        # for a private repo when the token is missing, expired, or lacks
        # contents:read.
        fail_fetch("HTTP %d (on a private repo, 404 usually means a "
                   "missing/expired/underscoped token)" % exc.code)
    except urllib.error.URLError as exc:
        fail_fetch("network error: %s" % getattr(exc, "reason", exc))
    except (TimeoutError, OSError) as exc:
        fail_fetch("network error: %s" % type(exc).__name__)
    size = os.path.getsize(tar_path)
    log("tarball fetched: %d bytes" % size)
    if size < 64:
        fail_fetch("response is too small to be a tarball (%d bytes)" % size)
    return tar_path


def safe_extract(tar_path, dest_dir):
    out_dir = os.path.join(dest_dir, "src")
    os.mkdir(out_dir)
    try:
        tar = tarfile.open(tar_path, "r:gz")
    except tarfile.TarError:
        fail_fetch("fetched file is not a gzip tarball")
        return  # unreachable
    with tar:
        # Load-bearing vetting loop: filter="data" is not available (or not
        # trustworthy, see the 2025 tarfile filter-bypass CVEs) on every
        # runner Python, so these checks must stay even where the filter
        # exists.
        for member in tar.getmembers():
            parts = member.name.split("/")
            if member.name.startswith("/") or ".." in parts:
                fail_config("unsafe tar member path: %r" % member.name)
            if member.issym() or member.islnk():
                target_parts = member.linkname.split("/")
                if member.linkname.startswith("/") or ".." in target_parts:
                    fail_config("unsafe tar link target in: %r" % member.name)
            if not (member.isreg() or member.isdir()
                    or member.issym() or member.islnk()):
                fail_config("unsupported tar member type: %r" % member.name)
        try:
            tar.extractall(out_dir, filter="data")  # py>=3.12 / backports
        except TypeError:
            tar.extractall(out_dir)  # members were vetted above
    entries = [e for e in os.listdir(out_dir) if not e.startswith(".")]
    if len(entries) == 1 and os.path.isdir(os.path.join(out_dir, entries[0])):
        root = os.path.join(out_dir, entries[0])  # GitHub-style single top dir
    else:
        root = out_dir
    log("extracted to " + root)
    return root


def resolve_masked_env(config_url, key_var):
    masked = sorted(k for k, v in os.environ.items() if v == "***")
    if not masked:
        log("resolve-masked: no masked env vars found")
        return
    base_urls = [u for u in config_url.split() if u]
    if not base_urls:
        fail_config("BOOTSTRAP_CONFIG_URL is required in "
                    "BOOTSTRAP_RESOLVE_MASKED=auto mode (space-separated "
                    "base URLs are tried in order)")
    for u in base_urls:
        host = urllib.parse.urlsplit(u).hostname or ""
        if not (u.startswith("https://")
                or (u.startswith("http://") and host.endswith(".svc.cluster.local"))):
            fail_config("BOOTSTRAP_CONFIG_URL entries must be https:// "
                        "(plain http only for cluster-internal "
                        ".svc.cluster.local hosts): %r" % u)
    api_key = os.environ.get(key_var, "").strip()
    if not api_key:
        fail_config("resolve-masked: env var %r (BOOTSTRAP_CONFIG_KEY_VAR) "
                    "is empty" % key_var)
    log("resolve-masked: %d masked vars: %s" % (len(masked), ", ".join(masked)))
    config_path = os.environ.get("BOOTSTRAP_CONFIG_PATH", "/api/v1/config").strip()
    if not config_path.startswith("/"):
        config_path = "/" + config_path
    osc_token = os.environ.get("OSC_ACCESS_TOKEN", "")
    # Auth contracts differ between config-service frontends; try the known
    # variants in order and use the first that is not rejected.
    variants = [
        ("bearer-apikey", {"Authorization": "Bearer " + api_key,
                           "x-config-api-key": api_key}),
        ("x-config-api-key-only", {"x-config-api-key": api_key}),
    ]
    if osc_token:
        variants.append(("x-config-api-key+osc-bearer",
                         {"x-config-api-key": api_key,
                          "Authorization": "Bearer " + osc_token}))
    opener = urllib.request.build_opener(_SafeRedirectHandler)
    body = None
    last_err = "no base URL or auth variant attempted"
    for base in base_urls:
        if body is not None:
            break
        url = base.rstrip("/") + config_path
        shown_host = urllib.parse.urlsplit(base).hostname or base
        for variant_name, headers in variants:
            request = urllib.request.Request(url)
            request.add_header("User-Agent", "osc-job-bootstrap")
            for h, v in headers.items():
                request.add_header(h, v)
            try:
                resp = opener.open(request, timeout=30)
                try:
                    body = resp.read()
                finally:
                    resp.close()
                log("resolve-masked: config read OK (host %s, auth variant %s)"
                    % (shown_host, variant_name))
                break
            except urllib.error.HTTPError as exc:
                last_err = "HTTP %d (host %s, variant %s)" % (
                    exc.code, shown_host, variant_name)
                log("resolve-masked: " + last_err)
                if exc.code in (401, 403, 404):
                    continue
                fail_fetch("config read failed: " + last_err)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                reason = getattr(exc, "reason", exc)
                last_err = "%s (host %s)" % (type(reason).__name__ if not
                    isinstance(reason, str) else reason, shown_host)
                log("resolve-masked: unreachable: " + last_err)
                break  # next base URL, all variants would fail the same way
    if body is None:
        fail_fetch("config read failed on all base URLs and auth variants, "
                   "last: " + last_err)
    import json
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        fail_fetch("config read returned non-JSON")
        return  # unreachable
    if isinstance(data, dict) and isinstance(data.get("config"), dict):
        data = data["config"]
    if isinstance(data, list):
        data = {e.get("key"): e.get("value") for e in data if isinstance(e, dict)}
    if not isinstance(data, dict):
        fail_fetch("config read returned an unexpected JSON shape")
        return  # unreachable
    resolved, unresolved = [], []
    for name in masked:
        value = data.get(name)
        if isinstance(value, str) and value and value != "***":
            os.environ[name] = value
            resolved.append(name)
        else:
            unresolved.append(name)
    log("resolve-masked: resolved %d (%s)" % (len(resolved), ", ".join(resolved) or "-"))
    if unresolved:
        log("resolve-masked: WARNING, still masked: %s" % ", ".join(unresolved))
    os.environ.pop(key_var, None)


def parse_steps(raw):
    steps = []
    for line in raw.replace(" && ", "\n").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            argv = shlex.split(line)
        except ValueError as exc:
            fail_config("bad quoting in step %r: %s (note: \" && \" is a "
                        "textual separator and cannot appear inside quoted "
                        "arguments, use newline separation)" % (line, exc))
        if not argv:
            continue
        if any("&&" in tok for tok in argv):
            fail_config("step %r contains a '&&' token; separate commands "
                        "with \" && \" (spaces required) or newlines" % line)
        # Pin bare "python" to the runner's interpreter.
        if argv[0] in ("python", "python3"):
            argv[0] = sys.executable
        steps.append(argv)
    if not steps:
        fail_config("BOOTSTRAP_STEPS is set but contains no commands")
    return steps


def run_steps(repo_root, steps, timeout_s):
    for i, argv in enumerate(steps, start=1):
        shown = " ".join(argv)
        log("STEP %d/%d: %s" % (i, len(steps), shown))
        started = time.monotonic()
        try:
            result = subprocess.run(argv, cwd=repo_root, timeout=timeout_s)
        except FileNotFoundError:
            log("STEP %d FAILED: command not found: %s" % (i, argv[0]))
            sys.exit(127)
        except subprocess.TimeoutExpired:
            log("STEP %d FAILED: timeout after %ds" % (i, timeout_s))
            sys.exit(124)
        elapsed = time.monotonic() - started
        if result.returncode != 0:
            log("STEP %d FAILED exit=%d (%.1fs)" % (i, result.returncode, elapsed))
            sys.exit(result.returncode)
        log("STEP %d OK (%.1fs)" % (i, elapsed))
    log("all steps OK")


def parse_cli(argv):
    require_repo = None
    args = list(argv)
    while args:
        arg = args.pop(0)
        if arg == "--require-repo":
            if not args:
                fail_config("--require-repo needs a value (OWNER/REPO)")
            require_repo = args.pop(0)
            if not re.fullmatch(r"[\w.-]+/[\w.-]+", require_repo):
                fail_config("--require-repo value must be OWNER/REPO")
        else:
            fail_config("unknown argument: %r" % arg)
    return require_repo


def main():
    require_repo = parse_cli(sys.argv[1:])
    if not require_repo:
        env_pin = os.environ.get("BOOTSTRAP_REQUIRE_REPO", "").strip()
        if env_pin:
            if not re.fullmatch(r"[\w.-]+/[\w.-]+", env_pin):
                fail_config("BOOTSTRAP_REQUIRE_REPO must be OWNER/REPO")
            require_repo = env_pin
    mode = os.environ.get("BOOTSTRAP_MODE", "probe").strip().lower()
    if mode == "probe":
        probe()
        return
    if mode != "run":
        fail_config("unknown BOOTSTRAP_MODE %r (use 'probe' or 'run')" % mode)

    url = os.environ.get("BOOTSTRAP_TARBALL_URL", "").strip()
    raw_b64 = os.environ.get("BOOTSTRAP_STEPS_B64", "").strip()
    if raw_b64:
        try:
            raw_steps = base64.b64decode(raw_b64, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            fail_config("BOOTSTRAP_STEPS_B64 is not valid base64 UTF-8: %s"
                        % type(exc).__name__)
            return  # unreachable
    else:
        raw_steps = os.environ.get("BOOTSTRAP_STEPS", "")
    if not url:
        fail_config("run mode requires BOOTSTRAP_TARBALL_URL")
    if not raw_steps.strip():
        fail_config("run mode requires BOOTSTRAP_STEPS (or BOOTSTRAP_STEPS_B64)")
    token_var = os.environ.get("BOOTSTRAP_TOKEN_VAR", DEFAULT_TOKEN_VAR).strip()
    try:
        timeout_s = int(os.environ.get("BOOTSTRAP_STEP_TIMEOUT", "1800"))
    except ValueError:
        fail_config("BOOTSTRAP_STEP_TIMEOUT must be an integer (seconds)")
        return  # unreachable
    if timeout_s <= 0:
        fail_config("BOOTSTRAP_STEP_TIMEOUT must be positive")
    steps = parse_steps(raw_steps)

    work = tempfile.mkdtemp(prefix="bootstrap-")
    try:
        tar_path = fetch_tarball(url, token_var, work, require_repo)
        repo_root = safe_extract(tar_path, work)
        # The fetch token's job is done; keep it away from pip and the steps.
        os.environ.pop(token_var, None)
        if os.environ.get("BOOTSTRAP_RESOLVE_MASKED", "").strip().lower() == "auto":
            resolve_masked_env(
                os.environ.get("BOOTSTRAP_CONFIG_URL", "").strip(),
                os.environ.get("BOOTSTRAP_CONFIG_KEY_VAR", "CONFIG_API_KEY").strip(),
            )
        pip_args = os.environ.get("BOOTSTRAP_PIP_ARGS", "").strip()
        if pip_args:
            argv = [sys.executable, "-m", "pip", "install"] + shlex.split(pip_args)
            log("pip install: " + " ".join(argv[4:]))
            try:
                result = subprocess.run(argv, cwd=repo_root, timeout=timeout_s)
            except subprocess.TimeoutExpired:
                log("pip install FAILED: timeout after %ds" % timeout_s)
                sys.exit(124)
            if result.returncode != 0:
                log("pip install FAILED exit=%d" % result.returncode)
                sys.exit(result.returncode)
        run_steps(repo_root, steps, timeout_s)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
