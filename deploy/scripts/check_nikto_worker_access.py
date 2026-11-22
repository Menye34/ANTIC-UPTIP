#!/usr/bin/env python3
"""Read-only check of the worker account's access to the installed Kali Nikto."""
import argparse
import os
import pathlib
import pwd
import subprocess
import sys


def check(executable: str, expected_user: str) -> list[str]:
    problems = []
    account = pwd.getpwnam(expected_user)
    if os.geteuid() != account.pw_uid:
        problems.append(f'Run as worker account {expected_user!r}, not UID {os.geteuid()}')
        return problems
    path = pathlib.Path(executable)
    if not path.is_absolute() or not path.is_file():
        return [f'Executable does not exist: {executable}']
    if not os.access(path, os.R_OK | os.X_OK):
        problems.append(f'Worker cannot read and execute {executable}')
    if problems:
        return problems
    try:
        result = subprocess.run([executable, '-Version'], shell=False, capture_output=True,
                                text=True, timeout=15, check=False,
                                env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                                     'HOME': '/nonexistent', 'PERL5OPT': ''})
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f'Nikto version probe failed: {exc}']
    output = result.stdout + result.stderr
    if result.returncode != 0 or 'Nikto' not in output:
        problems.append(f'Nikto version probe unsuccessful (exit={result.returncode})')
    else:
        print(output.strip())
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker-user', required=True)
    parser.add_argument('--executable', default='/usr/bin/nikto')
    args = parser.parse_args()
    try:
        problems = check(args.executable, args.worker_user)
    except KeyError:
        problems = [f'Worker account does not exist: {args.worker_user}']
    for problem in problems:
        print('FAIL: ' + problem, file=sys.stderr)
    if problems:
        return 1
    print('PASS: worker account can invoke Nikto -Version (no scan performed)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
