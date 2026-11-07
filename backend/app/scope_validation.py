import re
from ipaddress import IPv4Address, IPv4Network
from urllib.parse import urlsplit

LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', re.ASCII)
NUMERIC = re.compile(r'(?:[0-9]+|0x[0-9a-f]+)')


def hostname(value: str) -> str:
    host = value.lower()
    labels = host.removesuffix('.').split('.')
    if len(host.removesuffix('.')) > 253 or not all(LABEL.fullmatch(label) for label in labels):
        raise ValueError('Invalid hostname')
    if NUMERIC.fullmatch(labels[-1]):
        raise ValueError('Invalid numeric hostname')
    return host


def normalize(value: str) -> tuple[str, str]:
    value = value.strip()
    if not re.fullmatch(r'[!-~]{1,1024}', value) or any(char in value for char in '\\<>"'):
        raise ValueError('Invalid scope entry')
    if '://' in value:
        url = urlsplit(value)
        if url.scheme not in ('http', 'https') or not url.hostname or '@' in url.netloc or '#' in value:
            raise ValueError('Invalid web URL')
        if not re.fullmatch(r'[A-Za-z0-9.-]+(?::[0-9]+)?', url.netloc):
            raise ValueError('Invalid web authority')
        try:
            host = str(IPv4Address(url.hostname))
        except ValueError:
            host = hostname(url.hostname)
        port = url.port
        if port == 0 or re.search(r'%(?![0-9a-fA-F]{2})', value):
            raise ValueError('Invalid web URL')
        suffix = value.split('://', 1)[1][len(url.netloc):]
        authority = f'{host}:{port}' if port is not None else host
        return f'{url.scheme}://{authority}{suffix}', 'Web URL'
    if '/' in value:
        if not re.fullmatch(r'[0-9.]+/(?:0|[1-9][0-9]?)', value):
            raise ValueError('Invalid CIDR')
        return str(IPv4Network(value, strict=True)), 'Subnet'
    try:
        return str(IPv4Address(value)), 'IP address'
    except ValueError:
        return hostname(value), 'Hostname'
