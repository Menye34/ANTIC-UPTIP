"""Bounded, integrity-checked original evidence. Never accepts a filesystem path."""
from hashlib import sha256
from hmac import compare_digest
import os
from pathlib import PurePosixPath
import re
import stat

MAX_BYTES = 10 * 1024 * 1024


class EvidenceUnavailable(ValueError):
    pass


def read_original(row, directory=None):
    try:
        if type(row.size_bytes) is not int or not 0 <= row.size_bytes <= MAX_BYTES:
            raise EvidenceUnavailable()
        if not isinstance(row.content_hash, str) or not re.fullmatch('[0-9a-f]{64}', row.content_hash):
            raise EvidenceUnavailable()
        if (row.content is None) == (row.storage_key is None):
            raise EvidenceUnavailable()
        if row.content is not None:
            content = bytes(row.content)
        else:
            if not directory or not re.fullmatch(r'evidence/[0-9a-f]{32}', row.storage_key):
                raise EvidenceUnavailable()
            root = PurePosixPath(directory)
            if not root.is_absolute() or '..' in root.parts:
                raise EvidenceUnavailable()
            # Walk each directory component without following symlinks. Hold the
            # final directory descriptor across open/read; no path race fallback.
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                for part in root.parts[1:]:
                    nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    os.close(fd)
                    fd = nxt
                info = os.fstat(fd)
                if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise EvidenceUnavailable()
                file_fd = os.open(row.storage_key.split('/')[1],
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                with os.fdopen(file_fd, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or info.st_uid != os.geteuid() or info.st_mode & 0o077
                            or info.st_size != row.size_bytes):
                        raise EvidenceUnavailable()
                    content = stream.read(MAX_BYTES + 1)
            finally:
                os.close(fd)
        if len(content) != row.size_bytes or not compare_digest(sha256(content).hexdigest(), row.content_hash):
            raise EvidenceUnavailable()
        return content.decode('utf-8', errors='strict')
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        raise EvidenceUnavailable('Original evidence unavailable or failed integrity checks.') from None
