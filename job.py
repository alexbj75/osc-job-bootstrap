#!/usr/bin/env python3
"""Entry point for OSC runners that fall back to job.py when no worker
command reaches the instance. Identical to running "python bootstrap.py";
use the BOOTSTRAP_REQUIRE_REPO environment variable for the repo pin, since
no CLI arguments exist on this path."""

import bootstrap

if __name__ == "__main__":
    bootstrap.main()
