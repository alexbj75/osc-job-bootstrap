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

Security posture: no shell is ever invoked; environment VALUES are never
printed by the launcher; redirects are followed only to https URLs and the
Authorization header is dropped when a redirect changes host; tar members
with absolute paths, ".." components, or special types (devices, FIFOs) are
rejected.

Exit codes: 0 success, 2 configuration error, 3 fetch/unpack failure,
124 step or pip timeout, 127 command not found, otherwise the failing
step's exit code.
"""

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
    mode = os.environ.get("BOOTSTRAP_MODE", "probe").strip().lower()
    if mode == "probe":
        probe()
        return
    if mode != "run":
        fail_config("unknown BOOTSTRAP_MODE %r (use 'probe' or 'run')" % mode)

    url = os.environ.get("BOOTSTRAP_TARBALL_URL", "").strip()
    raw_steps = os.environ.get("BOOTSTRAP_STEPS", "")
    if not url:
        fail_config("run mode requires BOOTSTRAP_TARBALL_URL")
    if not raw_steps.strip():
        fail_config("run mode requires BOOTSTRAP_STEPS")
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
