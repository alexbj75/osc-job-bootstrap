# osc-job-bootstrap

A tiny, generic launcher for [Eyevinn Open Source Cloud](https://www.osaas.io)
scheduled jobs (My Jobs) whose real code lives somewhere the job runner
cannot clone directly, for example a **private** GitHub repository.

OSC My Jobs clone a public source repo and inject environment variables from
a bound parameter store. If your job's real code lives in a private
repository that the runner cannot authenticate to, point the job at THIS
public repo and let the launcher fetch your private code as a tarball at
runtime, using a read-only token injected from the parameter store.

Everything is driven by environment variables, so one job definition can be
re-pointed between runs (probe, dry-run, execute, different refs) purely by
updating parameters, without recreating the job.

## Usage

Create a My Job with:

- **Source URL**: this repository
- **Parameter store**: your store (holds both the config below and your
  private code's own runtime configuration)
- **Worker command**: `python bootstrap.py`, optionally with
  `--require-repo OWNER/REPO` (recommended, see Trust boundary)

Then set parameters:

| Variable | Meaning |
|---|---|
| `BOOTSTRAP_MODE` | `probe` (default): print env var NAMES only, verify injection. `run`: fetch + execute. |
| `BOOTSTRAP_TARBALL_URL` | e.g. `https://api.github.com/repos/OWNER/REPO/tarball/REF` |
| `BOOTSTRAP_TOKEN_VAR` | Name of the env var holding the bearer token (default `GITHUB_READ_PAT`). |
| `BOOTSTRAP_PIP_ARGS` | Optional `pip install` args run in the unpacked tree, e.g. `-r requirements.txt`. |
| `BOOTSTRAP_STEPS` | Commands to run in the unpacked tree, separated by newlines or ` && ` (spaces required). No shell is used. |
| `BOOTSTRAP_STEP_TIMEOUT` | Per-step (and pip) timeout in seconds (default 1800). |

Store the token itself (for example a fine-grained GitHub PAT with
`contents:read` on a single repository) as a **secret** parameter, and
rotate or revoke it when it is no longer needed.

Only `api.github.com` tarball URLs are tested. GitHub **release asset**
URLs are unsupported (their S3 redirect rejects requests that carry both an
Authorization header and a pre-signed query token).

Troubleshooting: GitHub answers **HTTP 404** (not 401/403) for a private
repository when the token is missing, expired, or lacks `contents:read`.

## Trust boundary

Anyone with write access to the bound parameter store fully controls what
code this job runs, with access to every variable in the store. Treat store
write access as equivalent to code execution with all the job's secrets.

The `--require-repo OWNER/REPO` worker-command flag pins the tarball source
to one GitHub repository. The worker command lives in the job definition,
not in the parameter store, so store writers cannot loosen the pin. Whoever
can edit the job definition itself can still change it.

The launcher also drops the fetch token from the environment before pip and
your steps run, follows redirects only to `https://` URLs, and removes the
Authorization header when a redirect changes host.

## Safety notes

- No shell is ever invoked; steps are `shlex`-split and executed directly.
  The ` && ` separator is textual: it cannot appear inside quoted
  arguments, use newline-separated commands for that.
- Environment variable VALUES are never printed **by the launcher**, in any
  mode. Your own steps inherit stdout, so whatever they print lands in the
  job log too.
- Step commands and pip args are echoed to the log: never pass secrets as
  command-line arguments, read them from the environment instead.
- Tar members with absolute paths, `..` components, unsafe link targets, or
  special types (devices, FIFOs) are rejected.
- Exit codes: `0` success, `2` configuration error, `3` fetch/unpack
  failure, `124` step or pip timeout, `127` command not found, otherwise
  the failing step's exit code.

## License

MIT, see [LICENSE](LICENSE).
