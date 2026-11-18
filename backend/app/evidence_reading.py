"""Read original output without granting access to worker paths or execution."""
from hashlib import sha256
from hmac import compare_digest
import os
import re
import stat

from .execution_results import MAX_OUTPUT


class EvidenceUnavailable(ValueError):
    """Safe error: never include private paths or scanner output."""


def original_output(row, root=None):
    if not 0 <= row.size_bytes <= MAX_OUTPUT:
        raise EvidenceUnavailable('output_unavailable')
    if row.content is not None:
        if row.storage_key is not None:
            raise EvidenceUnavailable('output_unavailable')
        content = bytes(row.content)
    else:
        if not root or not re.fullmatch(r'evidence/[0-9a-f]{32}', row.storage_key or ''):
            raise EvidenceUnavailable('output_unavailable')
        # Walk from / using directory descriptors. No symlinks, including parents,
        # can redirect the read. This never changes existing ownership/permissions.
        if not os.path.isabs(root) or any(p in ('.', '..', '') for p in root.split('/')[1:]):
            raise EvidenceUnavailable('output_unavailable')
        directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in root.split('/')[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise EvidenceUnavailable('output_unavailable')
            fd = os.open(row.storage_key.split('/')[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size != row.size_bytes):
                    raise EvidenceUnavailable('output_unavailable')
                content = stream.read(MAX_OUTPUT + 1)
        except OSError:
            raise EvidenceUnavailable('output_unavailable') from None
        finally:
            os.close(directory)
    if (len(content) != row.size_bytes or len(content) > MAX_OUTPUT
            or not compare_digest(sha256(content).hexdigest(), row.content_hash)):
        raise EvidenceUnavailable('output_unavailable')
    try:
        return content.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        raise EvidenceUnavailable('output_unavailable') from None
