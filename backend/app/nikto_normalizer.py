"""Conservative, offline normalization of Nikto's bounded text output.

This parser produces observations, not validated vulnerabilities. It never
executes a scanner, follows links, or interprets arbitrary output as commands.
"""
import re
from hashlib import sha256
from json import dumps

MAX_OUTPUT = 5 * 1024 * 1024
MAX_OBSERVATIONS = 500
MAX_LINE = 4096
VERSION = '3'

# Nikto emits informational '+' lines as well as URL-specific test results.
# Only explicit HTTP path lines become normalized test observations.
_PATH = re.compile(
    r'^\+\s+(?:\[(?P<test_id>\d{6})\]\s+)?'
    r'(?P<path>/[^\s:]*)(?::\s+|\s+-\s+)(?P<message>.+)$'
)
_MISSING_HEADER = re.compile(
    r'^\+\s+(?:The\s+)?(?P<header>'
    r'X-Content-Type-Options|Content-Security-Policy'
    r')\s+header\s+(?:is\s+)?'
    r'(?P<status>not set|not defined|missing)\b',
    re.I,
)

_REFERENCE = re.compile(r'\b(?:OSVDB-\d+|CVE-\d{4}-\d{4,}|CWE-\d+)\b', re.I)


def normalize(stdout: bytes, *, target: str, port: int, scheme: str) -> list[dict]:
    if not isinstance(stdout, bytes) or len(stdout) > MAX_OUTPUT:
        raise ValueError('invalid_nikto_output')
    if not isinstance(target, str) or type(port) is not int or scheme not in ('http', 'https'):
        raise ValueError('invalid_nikto_target')
    try:
        body = stdout.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        raise ValueError('nikto_output_not_utf8') from exc
    observations = []
    seen = set()
    for line in body.splitlines():
        if len(line) > MAX_LINE:
            continue
        match = _PATH.match(line)
        header_match = _MISSING_HEADER.match(line) if not match else None
        if not match and not header_match:
            continue
        if match:
            path, message = match.group('path'), match.group('message').strip()
        else:
            path = '/'
            message = line.removeprefix('+').strip()
        if not message or len(path) > 1024 or len(message) > 2048:
            continue
        data = {
            'tool': 'Nikto',
            'test_id': match.group('test_id') if match else None,
            'address': target,
            'port': port,
            'scheme': scheme,
            'path': path,
            'message': message,
            'references': sorted(set(_REFERENCE.findall(message)), key=str.lower)[:20],
            'verification': 'unverified',
        }
        canonical = dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
        key = sha256(canonical.encode('ascii')).hexdigest()
        if key in seen:
            continue
        seen.add(key)
        observations.append({'type': 'http_server_test', 'data': data, 'deduplication_key': key})
        if len(observations) >= MAX_OBSERVATIONS:
            raise ValueError('nikto_observation_limit_exceeded')
    return observations
